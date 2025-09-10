import os
import requests
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app, origins=['http://localhost:5000', 'https://*.replit.app', 'https://*.replit.dev'])

# Get SERP API key from environment
SERPAPI_KEY = os.getenv('SERPAPI_API_KEY')

@app.route('/')
def index():
    return render_template_string(open('main.html').read())

@app.route('/search', methods=['POST'])
def search():
    try:
        data = request.get_json()
        query = data.get('query', '')
        country = data.get('country', 'us')
        
        if not query.strip():
            return jsonify({'error': 'Search query is required'}), 400
        
        # SERP API request
        params = {
            'q': query,
            'api_key': SERPAPI_KEY,
            'engine': 'google',
            'gl': country,
            'num': 10
        }
        
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
            
            return jsonify(results)
        elif response.status_code == 401:
            return jsonify({'error': 'Invalid SERP API key. Please check your API credentials.'}), 401
        elif response.status_code == 403:
            return jsonify({'error': 'Access denied. Your SERP API key may have insufficient permissions.'}), 403
        elif response.status_code == 429:
            return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
        else:
            return jsonify({'error': f'SERP API error: {response.status_code}'}), 500
            
    except requests.exceptions.Timeout:
        return jsonify({'error': 'Request timeout. The search service is taking too long to respond.'}), 504
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Network error: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'serpapi_configured': bool(SERPAPI_KEY)})

if __name__ == '__main__':
    if not SERPAPI_KEY:
        print("Error: SERPAPI_API_KEY not found in environment variables")
        print("Please set your SERP API key as an environment variable before running the application.")
        exit(1)
    app.run(host='0.0.0.0', port=5000, debug=False)