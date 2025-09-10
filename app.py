import os
import sqlite3
import requests
import datetime
import json
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app, origins=['http://localhost:5000', 'https://*.replit.app', 'https://*.replit.dev'])

# Get SERP API key from environment
SERPAPI_KEY = os.getenv('SERPAPI_API_KEY')

# Initialize database
def init_database():
    conn = sqlite3.connect('osint_searches.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS search_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT NOT NULL,
            user_agent TEXT,
            query TEXT NOT NULL,
            country TEXT NOT NULL,
            results_count INTEGER DEFAULT 0,
            success BOOLEAN DEFAULT TRUE,
            error_message TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

# Log search to database
def log_search(ip_address, user_agent, query, country, results_count=0, success=True, error_message=None):
    try:
        conn = sqlite3.connect('osint_searches.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO search_logs (ip_address, user_agent, query, country, results_count, success, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (ip_address, user_agent, query, country, results_count, success, error_message))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging search: {e}")

# Initialize database on startup
init_database()

@app.route('/')
def index():
    return render_template_string(open('main.html').read())

@app.route('/search', methods=['POST'])
def search():
    # Get client IP and user agent for logging
    # Extract the first IP from X-Forwarded-For header (client IP)
    forwarded_for = request.environ.get('HTTP_X_FORWARDED_FOR', '')
    if forwarded_for:
        client_ip = forwarded_for.split(',')[0].strip()
    else:
        client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
    
    user_agent = request.environ.get('HTTP_USER_AGENT', 'unknown')[:500]  # Limit length
    
    # Initialize variables for logging
    query = ''
    country = 'us'
    
    try:
        # Robust JSON parsing with comprehensive validation
        data = None
        
        
        # Handle different content types and payload formats
        if request.content_type and 'application/json' in request.content_type:
            try:
                raw_data = request.get_json(silent=True, force=True)
                # Handle various JSON payload types
                if raw_data is None:
                    log_search(client_ip, user_agent, query, country, 0, False, 'Empty JSON payload')
                    return jsonify({'error': 'Empty or malformed JSON payload'}), 400
                elif isinstance(raw_data, str):
                    # JSON string - try to parse it
                    try:
                        data = json.loads(raw_data)
                        if not isinstance(data, dict):
                            raise ValueError("JSON must be an object")
                    except (json.JSONDecodeError, ValueError):
                        log_search(client_ip, user_agent, query, country, 0, False, 'Invalid JSON string format')
                        return jsonify({'error': 'JSON payload must be a valid object'}), 400
                elif isinstance(raw_data, dict):
                    data = raw_data
                elif isinstance(raw_data, list):
                    log_search(client_ip, user_agent, query, country, 0, False, 'JSON array not supported')
                    return jsonify({'error': 'JSON payload must be an object, not an array'}), 400
                else:
                    log_search(client_ip, user_agent, query, country, 0, False, f'Unsupported JSON type: {type(raw_data).__name__}')
                    return jsonify({'error': f'Unsupported JSON payload type: {type(raw_data).__name__}'}), 400
            except Exception as e:
                log_search(client_ip, user_agent, query, country, 0, False, f'JSON parsing error: {str(e)}')
                return jsonify({'error': 'Failed to parse JSON payload'}), 400
        else:
            # Try form data as fallback
            data = request.form.to_dict()
            if not data:
                log_search(client_ip, user_agent, query, country, 0, False, 'No data provided')
                return jsonify({'error': 'No search data provided'}), 400
        
        # Validate and extract parameters
        if not isinstance(data, dict):
            log_search(client_ip, user_agent, query, country, 0, False, f'Data not dict: {type(data)} = {repr(data)}')
            return jsonify({'error': 'Invalid request format'}), 400
        
        # Extract and validate query
        raw_query = data.get('query', '')
        query = str(raw_query).strip() if raw_query is not None else ''
        
        # Extract and validate country
        raw_country = data.get('country', 'us')
        country = str(raw_country).lower() if raw_country is not None else 'us'
        
        # Validate country code
        valid_countries = ['us', 'gb', 'ca', 'au', 'de', 'fr', 'jp', 'cn', 'in', 'br', 'mx', 'ru', 'it', 'es', 'nl']
        if country not in valid_countries:
            country = 'us'
        
        # Extract and validate state (optional)
        raw_state = data.get('state', '')
        state = str(raw_state).lower().strip() if raw_state is not None else ''
        
        # Extract search type for targeted queries
        search_type = data.get('searchType', 'general')
        if not isinstance(search_type, str):
            search_type = 'general'
        
        if not query.strip():
            log_search(client_ip, user_agent, query, country, 0, False, 'Empty search query')
            return jsonify({'error': 'Search query is required'}), 400
        
        # Build targeted search query based on search type
        targeted_query = query
        
        # Add search type-specific terms for better OSINT results
        search_modifiers = {
            'criminal': f'"{query}" (arrest OR criminal OR conviction OR mugshot OR court)',
            'court': f'"{query}" (lawsuit OR court case OR civil OR judgment)',
            'warrants': f'"{query}" (warrant OR wanted OR fugitive)',
            'bankruptcy': f'"{query}" (bankruptcy OR chapter 7 OR chapter 11 OR debt)',
            'property': f'"{query}" (property records OR real estate OR deed OR owner)',
            'deeds': f'"{query}" (deed OR mortgage OR property transfer)',
            'foreclosure': f'"{query}" (foreclosure OR tax lien OR sheriff sale)',
            'business_property': f'"{query}" (commercial property OR business real estate)',
            'birth': f'"{query}" (birth certificate OR birth record OR born)',
            'death': f'"{query}" (death certificate OR obituary OR died OR deceased)',
            'marriage': f'"{query}" (marriage certificate OR wedding OR married OR divorce)',
            'address': f'"{query}" (address OR residence OR lived OR home)',
            'phone': f'"{query}" (phone number OR telephone OR contact)',
            'licenses': f'"{query}" (professional license OR certification OR permit)',
            'business': f'"{query}" (business registration OR LLC OR corporation OR company)',
            'employment': f'"{query}" (employment OR job OR work OR employer)',
            'education': f'"{query}" (education OR school OR university OR degree OR alumni)',
            'patents': f'"{query}" (patent OR trademark OR intellectual property)',
            'assets': f'"{query}" (assets OR wealth OR financial OR investments)',
            'corporations': f'"{query}" (corporation OR SEC filing OR executive OR officer)',
            'sec': f'"{query}" (SEC filing OR insider trading OR executive compensation)',
            'tax': f'"{query}" (tax records OR IRS OR tax lien OR assessment)',
            'vehicles': f'"{query}" (vehicle registration OR car OR license plate)',
            'drivers': f'"{query}" (drivers license OR driving record OR DMV OR DUI)',
            'aviation': f'"{query}" (aircraft registration OR pilot license OR FAA)',
            'social': f'"{query}" (Facebook OR Twitter OR Instagram OR LinkedIn OR social media)',
            'online': f'"{query}" (username OR profile OR account OR online)',
            'breaches': f'"{query}" (data breach OR password leak OR hack OR exposed)',
            'websites': f'"{query}" (domain registration OR website owner OR WHOIS)',
            'medical': f'"{query}" (medical license OR doctor OR physician OR MD)',
            'sanctions': f'"{query}" (medical sanctions OR excluded provider OR Medicare fraud)',
            'prescribers': f'"{query}" (DEA prescriber OR controlled substance OR prescription)',
            'news_criminal': f'"{query}" (arrested OR charged OR convicted OR crime news)',
            'news_business': f'"{query}" (CEO OR executive OR business news OR scandal)',
            'investigations': f'"{query}" (investigation OR expose OR corruption OR fraud)',
            'media': f'"{query}" (interview OR news OR media OR press OR appearance)',
            'academic': f'"{query}" (research OR publication OR academic OR scholar)',
            'research': f'"{query}" (research paper OR citation OR study OR journal)',
            'grants': f'"{query}" (research grant OR funding OR NSF OR NIH)',
            'university': f'"{query}" (university OR college OR alumni OR faculty)',
            'military': f'"{query}" (military service OR veteran OR armed forces)',
            'immigration': f'"{query}" (immigration OR visa OR naturalization OR USCIS)',
            'political': f'"{query}" (political contribution OR campaign OR PAC OR lobbying)',
            'nonprofit': f'"{query}" (nonprofit OR charity OR 501c3 OR foundation)',
            'voter': f'"{query}" (voter registration OR voting record OR election)'
        }
        
        if search_type in search_modifiers:
            targeted_query = search_modifiers[search_type]
        
        # Add state parameter if provided (for location-specific searches)
        if state:
            # For US, Canada, Australia - add state/province to query for better location targeting
            if country in ['us', 'ca', 'au']:
                targeted_query = f"{targeted_query} {state}"
        
        # SERP API request with targeted query
        params = {
            'q': targeted_query,
            'api_key': SERPAPI_KEY,
            'engine': 'google',
            'gl': country,
            'num': 10
        }
        
        print(f"DEBUG: Using targeted query: {targeted_query}")  # Temporary debug
        
        response = requests.get('https://serpapi.com/search', params=params, timeout=10)
        
        if response.status_code == 200:
            search_results = response.json()
            
            # Extract comprehensive OSINT information
            results = {
                'query': query,
                'country': country,
                'search_information': search_results.get('search_information'),
                'organic_results': [],
                'news_results': [],
                'image_results': [],
                'video_results': [],
                'people_also_ask': [],
                'related_searches': [],
                'local_results': [],
                'shopping_results': [],
                'scholarly_articles': [],
                'knowledge_graph': search_results.get('knowledge_graph'),
                'answer_box': search_results.get('answer_box'),
                'top_stories': [],
                'raw_data': search_results  # Full JSON for advanced users
            }
            
            # Process organic results with enhanced metadata
            if 'organic_results' in search_results:
                for result in search_results['organic_results']:
                    organic_item = {
                        'position': result.get('position', 0),
                        'title': result.get('title', ''),
                        'link': result.get('link', ''),
                        'snippet': result.get('snippet', ''),
                        'displayed_link': result.get('displayed_link', ''),
                        'cached_page_link': result.get('cached_page_link', ''),
                        'related_pages_link': result.get('related_pages_link', ''),
                        'source_info': {
                            'domain': result.get('link', '').split('/')[2] if result.get('link', '').startswith('http') else '',
                            'favicon': result.get('favicon'),
                        },
                        'rich_snippet': result.get('rich_snippet'),
                        'sitelinks': result.get('sitelinks', []),
                        'thumbnail': result.get('thumbnail')
                    }
                    results['organic_results'].append(organic_item)
            
            # Process news results with enhanced metadata
            if 'news_results' in search_results:
                for result in search_results['news_results']:
                    news_item = {
                        'position': result.get('position', 0),
                        'title': result.get('title', ''),
                        'link': result.get('link', ''),
                        'snippet': result.get('snippet', ''),
                        'source': result.get('source', ''),
                        'date': result.get('date', ''),
                        'thumbnail': result.get('thumbnail'),
                        'stories': result.get('stories', [])  # Related stories
                    }
                    results['news_results'].append(news_item)
            
            # Process image results for visual OSINT
            if 'images_results' in search_results:
                for result in search_results['images_results']:
                    image_item = {
                        'position': result.get('position', 0),
                        'thumbnail': result.get('thumbnail', ''),
                        'source': result.get('source', ''),
                        'title': result.get('title', ''),
                        'link': result.get('link', ''),
                        'original': result.get('original', ''),
                        'original_width': result.get('original_width'),
                        'original_height': result.get('original_height'),
                        'is_product': result.get('is_product', False)
                    }
                    results['image_results'].append(image_item)
            
            # Process video results
            if 'video_results' in search_results:
                for result in search_results['video_results']:
                    video_item = {
                        'position': result.get('position', 0),
                        'title': result.get('title', ''),
                        'link': result.get('link', ''),
                        'displayed_link': result.get('displayed_link', ''),
                        'thumbnail': result.get('thumbnail', ''),
                        'duration': result.get('duration', ''),
                        'platform': result.get('platform', ''),
                        'date': result.get('date', '')
                    }
                    results['video_results'].append(video_item)
            
            # Process People Also Ask for related queries
            if 'people_also_ask' in search_results:
                for result in search_results['people_also_ask']:
                    paa_item = {
                        'question': result.get('question', ''),
                        'snippet': result.get('snippet', ''),
                        'title': result.get('title', ''),
                        'link': result.get('link', ''),
                        'displayed_link': result.get('displayed_link', ''),
                        'thumbnail': result.get('thumbnail')
                    }
                    results['people_also_ask'].append(paa_item)
            
            # Process related searches
            if 'related_searches' in search_results:
                for result in search_results['related_searches']:
                    related_item = {
                        'query': result.get('query', ''),
                        'link': result.get('link', '')
                    }
                    results['related_searches'].append(related_item)
            
            # Process local results (maps, businesses)
            if 'local_results' in search_results:
                for result in search_results['local_results']:
                    local_item = {
                        'position': result.get('position', 0),
                        'title': result.get('title', ''),
                        'place_id': result.get('place_id', ''),
                        'data_id': result.get('data_id', ''),
                        'data_cid': result.get('data_cid', ''),
                        'reviews_link': result.get('reviews_link', ''),
                        'photos_link': result.get('photos_link', ''),
                        'gps_coordinates': result.get('gps_coordinates', {}),
                        'place_id_search': result.get('place_id_search', ''),
                        'provider_id': result.get('provider_id', ''),
                        'rating': result.get('rating'),
                        'reviews': result.get('reviews'),
                        'price': result.get('price', ''),
                        'type': result.get('type', ''),
                        'types': result.get('types', []),
                        'type_id': result.get('type_id', ''),
                        'address': result.get('address', ''),
                        'open_state': result.get('open_state', ''),
                        'hours': result.get('hours', ''),
                        'operating_hours': result.get('operating_hours', {}),
                        'phone': result.get('phone', ''),
                        'website': result.get('website', ''),
                        'description': result.get('description', ''),
                        'service_options': result.get('service_options', {}),
                        'thumbnail': result.get('thumbnail')
                    }
                    results['local_results'].append(local_item)
            
            # Process shopping results
            if 'shopping_results' in search_results:
                for result in search_results['shopping_results']:
                    shopping_item = {
                        'position': result.get('position', 0),
                        'title': result.get('title', ''),
                        'link': result.get('link', ''),
                        'product_link': result.get('product_link', ''),
                        'product_id': result.get('product_id', ''),
                        'serpapi_product_api': result.get('serpapi_product_api', ''),
                        'source': result.get('source', ''),
                        'price': result.get('price', ''),
                        'extracted_price': result.get('extracted_price'),
                        'rating': result.get('rating'),
                        'reviews': result.get('reviews'),
                        'extensions': result.get('extensions', []),
                        'thumbnail': result.get('thumbnail'),
                        'delivery': result.get('delivery', '')
                    }
                    results['shopping_results'].append(shopping_item)
            
            # Process scholarly articles
            if 'scholarly_articles' in search_results:
                for result in search_results['scholarly_articles']:
                    scholarly_item = {
                        'position': result.get('position', 0),
                        'title': result.get('title', ''),
                        'link': result.get('link', ''),
                        'snippet': result.get('snippet', ''),
                        'publication_info': result.get('publication_info', {}),
                        'resources': result.get('resources', []),
                        'inline_links': result.get('inline_links', {})
                    }
                    results['scholarly_articles'].append(scholarly_item)
            
            # Process top stories
            if 'top_stories' in search_results:
                for result in search_results['top_stories']:
                    story_item = {
                        'position': result.get('position', 0),
                        'title': result.get('title', ''),
                        'link': result.get('link', ''),
                        'snippet': result.get('snippet', ''),
                        'date': result.get('date', ''),
                        'source': result.get('source', ''),
                        'thumbnail': result.get('thumbnail')
                    }
                    results['top_stories'].append(story_item)
            
            # Count total results
            total_results = (len(results.get('organic_results', [])) + 
                           len(results.get('news_results', [])) +
                           len(results.get('image_results', [])) +
                           len(results.get('video_results', [])) +
                           len(results.get('local_results', [])) +
                           len(results.get('shopping_results', [])) +
                           len(results.get('scholarly_articles', [])) +
                           len(results.get('top_stories', [])))
            
            # Log successful search (include search type and state info)
            logged_query = f"[{search_type.upper()}] {query}"
            if state:
                logged_query = f"{logged_query} [{state.upper()}]"
            log_search(client_ip, user_agent, logged_query, country, total_results, True, None)
            print(f"DEBUG: Logged query: {logged_query}")  # Temporary debug
            
            return jsonify(results)
        elif response.status_code == 401:
            log_search(client_ip, user_agent, query, country, 0, False, 'Invalid SERP API key')
            return jsonify({'error': 'Invalid SERP API key. Please check your API credentials.'}), 401
        elif response.status_code == 403:
            log_search(client_ip, user_agent, query, country, 0, False, 'Access denied - insufficient permissions')
            return jsonify({'error': 'Access denied. Your SERP API key may have insufficient permissions.'}), 403
        elif response.status_code == 429:
            log_search(client_ip, user_agent, query, country, 0, False, 'Rate limit exceeded')
            return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
        else:
            error_msg = f'SERP API error: {response.status_code}'
            log_search(client_ip, user_agent, query, country, 0, False, error_msg)
            return jsonify({'error': error_msg}), 500
            
    except requests.exceptions.Timeout:
        log_search(client_ip, user_agent, query, country, 0, False, 'Request timeout')
        return jsonify({'error': 'Request timeout. The search service is taking too long to respond.'}), 504
    except requests.exceptions.RequestException as e:
        error_msg = f'Network error: {str(e)}'
        log_search(client_ip, user_agent, query, country, 0, False, error_msg)
        return jsonify({'error': error_msg}), 500
    except Exception as e:
        error_msg = str(e)
        log_search(client_ip, user_agent, query, country, 0, False, error_msg)
        return jsonify({'error': error_msg}), 500

@app.route('/search-history')
def search_history():
    try:
        conn = sqlite3.connect('osint_searches.db')
        cursor = conn.cursor()
        
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 100)  # Limit max per page
        offset = (page - 1) * per_page
        
        # Get total count
        cursor.execute('SELECT COUNT(*) FROM search_logs')
        total_count = cursor.fetchone()[0]
        
        # Get search logs with pagination
        cursor.execute('''
            SELECT id, timestamp, ip_address, user_agent, query, country, 
                   results_count, success, error_message
            FROM search_logs 
            ORDER BY timestamp DESC 
            LIMIT ? OFFSET ?
        ''', (per_page, offset))
        
        logs = []
        for row in cursor.fetchall():
            logs.append({
                'id': row[0],
                'timestamp': row[1],
                'ip_address': row[2],
                'user_agent': row[3],
                'query': row[4],
                'country': row[5],
                'results_count': row[6],
                'success': bool(row[7]),
                'error_message': row[8]
            })
        
        conn.close()
        
        return jsonify({
            'logs': logs,
            'total_count': total_count,
            'page': page,
            'per_page': per_page,
            'total_pages': (total_count + per_page - 1) // per_page
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/search-stats')
def search_stats():
    try:
        conn = sqlite3.connect('osint_searches.db')
        cursor = conn.cursor()
        
        # Get basic statistics
        cursor.execute('SELECT COUNT(*) FROM search_logs')
        total_searches = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM search_logs WHERE success = 1')
        successful_searches = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(DISTINCT ip_address) FROM search_logs')
        unique_ips = cursor.fetchone()[0]
        
        # Get top queries
        cursor.execute('''
            SELECT query, COUNT(*) as count 
            FROM search_logs 
            WHERE success = 1
            GROUP BY query 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        top_queries = [{'query': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Get top countries
        cursor.execute('''
            SELECT country, COUNT(*) as count 
            FROM search_logs 
            WHERE success = 1
            GROUP BY country 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        top_countries = [{'country': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Get searches by day (last 7 days)
        cursor.execute('''
            SELECT DATE(timestamp) as date, COUNT(*) as count 
            FROM search_logs 
            WHERE timestamp >= datetime('now', '-7 days')
            GROUP BY DATE(timestamp)
            ORDER BY date DESC
        ''')
        daily_searches = [{'date': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({
            'total_searches': total_searches,
            'successful_searches': successful_searches,
            'unique_ips': unique_ips,
            'success_rate': round((successful_searches / total_searches * 100), 2) if total_searches > 0 else 0,
            'top_queries': top_queries,
            'top_countries': top_countries,
            'daily_searches': daily_searches
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    # Also check database health
    db_healthy = False
    try:
        conn = sqlite3.connect('osint_searches.db')
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM search_logs')
        conn.close()
        db_healthy = True
    except Exception:
        pass
    
    return jsonify({
        'status': 'healthy', 
        'serpapi_configured': bool(SERPAPI_KEY),
        'database_healthy': db_healthy
    })

if __name__ == '__main__':
    if not SERPAPI_KEY:
        print("Error: SERPAPI_API_KEY not found in environment variables")
        print("Please set your SERP API key as an environment variable before running the application.")
        exit(1)
    app.run(host='0.0.0.0', port=5000, debug=False)