# OmiOSINT

## Overview

OmiOSINT is a reconnaissance tool designed for gathering open-source intelligence (OSINT) information. The application provides a web-based interface for conducting searches and logging investigative activities. It's built as a Flask web application with a modern frontend interface that allows users to perform OSINT searches while maintaining comprehensive logs of all search activities for audit and analysis purposes.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Single-page web application** using vanilla HTML, CSS, and JavaScript
- **Responsive design** with modern CSS styling including gradients and glassmorphism effects
- **Real-time search interface** that communicates with the backend via AJAX requests
- **Cross-origin resource sharing (CORS)** enabled for development and deployment flexibility

### Backend Architecture
- **Flask web framework** serving as the main application server
- **RESTful API design** for handling search requests and data retrieval
- **Environment-based configuration** using python-dotenv for secure API key management
- **Request logging middleware** that captures user interactions and search metadata
- **Error handling and response formatting** for consistent API responses

### Data Storage
- **SQLite database** for storing search logs and user activity
- **Structured logging schema** including timestamps, IP addresses, user agents, queries, and results metadata
- **Database initialization** handled automatically on application startup
- **Search audit trail** maintaining comprehensive records of all OSINT activities

### External Service Integration
- **SERP API integration** for conducting web searches and gathering intelligence data
- **IP geolocation** for tracking search origins by country
- **User agent tracking** for device and browser identification

## External Dependencies

### APIs and Services
- **SERP API** - Primary search engine results API for OSINT data gathering
- **Environment variables** - Secure API key storage via .env files

### Python Libraries
- **Flask** - Web framework and HTTP server
- **Flask-CORS** - Cross-origin resource sharing support
- **requests** - HTTP client for external API calls
- **sqlite3** - Database connectivity and operations
- **python-dotenv** - Environment variable management
- **datetime** - Timestamp generation for search logging
- **json** - Data serialization for API responses

### Development Environment
- **Replit compatibility** - Configured for deployment on Replit platform
- **Local development support** - CORS configured for localhost testing
- **SQLite database** - Lightweight, file-based database requiring no external setup