"""
API Security Testing Module
Support for REST and GraphQL API security testing
"""

import asyncio
import json
import logging
import re
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Union, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
import requests
import aiohttp
import jwt
from dataclasses import dataclass

from core.config_manager import ConfigManager
from core.logger import get_security_logger

@dataclass
class APIEndpoint:
    """API endpoint information"""
    url: str
    method: str
    path_params: List[str] = None
    query_params: List[str] = None
    headers: Dict[str, str] = None
    auth_required: bool = False
    rate_limited: bool = False
    
    def __post_init__(self):
        if self.path_params is None:
            self.path_params = []
        if self.query_params is None:
            self.query_params = []
        if self.headers is None:
            self.headers = {}

class APITestResult:
    """API test result container"""
    
    def __init__(self, test_name: str, endpoint: APIEndpoint):
        self.test_name = test_name
        self.endpoint = endpoint
        self.status = 'pending'  # pending, running, passed, failed, error
        self.severity = 'info'
        self.findings = []
        self.evidence = {}
        self.start_time = None
        self.end_time = None
        self.error = None
    
    def add_finding(self, description: str, evidence: Dict[str, Any] = None, severity: str = 'info'):
        """Add a finding to the test result"""
        finding = {
            'description': description,
            'evidence': evidence or {},
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        self.findings.append(finding)
        
        # Update overall severity
        severity_levels = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        if severity_levels.get(severity, 0) > severity_levels.get(self.severity, 0):
            self.severity = severity
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'test_name': self.test_name,
            'endpoint': {
                'url': self.endpoint.url,
                'method': self.endpoint.method,
                'path_params': self.endpoint.path_params,
                'query_params': self.endpoint.query_params
            },
            'status': self.status,
            'severity': self.severity,
            'findings': self.findings,
            'evidence': self.evidence,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'error': self.error
        }

class APISecurityScanner:
    """API security testing framework"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        self.security_logger = get_security_logger(__name__)
        
        # HTTP session for synchronous requests
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 30
        
        # Test results storage
        self.test_results = []
        
        # Common injection payloads
        self.sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT NULL,NULL,NULL--",
            "admin'--",
            "' OR 1=1--"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>"
        ]
        
        self.xxe_payloads = [
            """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>""",
            """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'http://attacker.com/'>]><root>&test;</root>"""
        ]
        
        # Common authentication bypass patterns
        self.auth_bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Override-URL': '/admin'}
        ]
    
    async def discover_endpoints(self, base_url: str, options: Dict[str, Any] = None) -> List[APIEndpoint]:
        """Discover API endpoints from various sources"""
        if options is None:
            options = {}
        
        endpoints = []
        
        # Try to get OpenAPI/Swagger spec
        swagger_endpoints = await self._discover_from_swagger(base_url)
        endpoints.extend(swagger_endpoints)
        
        # Try to discover from robots.txt and sitemap
        discovery_endpoints = await self._discover_from_standard_files(base_url)
        endpoints.extend(discovery_endpoints)
        
        # Try common API paths
        common_endpoints = await self._discover_common_paths(base_url)
        endpoints.extend(common_endpoints)
        
        # GraphQL introspection
        graphql_endpoints = await self._discover_graphql(base_url)
        endpoints.extend(graphql_endpoints)
        
        self.logger.info(f"Discovered {len(endpoints)} API endpoints")
        return endpoints
    
    async def _discover_from_swagger(self, base_url: str) -> List[APIEndpoint]:
        """Discover endpoints from OpenAPI/Swagger documentation"""
        endpoints = []
        swagger_paths = [
            '/swagger.json',
            '/swagger.yaml',
            '/api/swagger.json',
            '/api/swagger.yaml',
            '/api-docs',
            '/swagger-ui.html',
            '/docs',
            '/api/docs',
            '/openapi.json',
            '/openapi.yaml'
        ]
        
        async with aiohttp.ClientSession() as session:
            for path in swagger_paths:
                try:
                    swagger_url = urljoin(base_url, path)
                    async with session.get(swagger_url) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Try to parse as JSON
                            try:
                                spec = json.loads(content)
                                endpoints.extend(self._parse_openapi_spec(base_url, spec))
                            except json.JSONDecodeError:
                                # Try YAML parsing if available
                                try:
                                    import yaml
                                    spec = yaml.safe_load(content)
                                    endpoints.extend(self._parse_openapi_spec(base_url, spec))
                                except:
                                    pass
                            
                            self.logger.info(f"Found API documentation at {swagger_url}")
                            break
                            
                except Exception as e:
                    continue
        
        return endpoints
    
    def _parse_openapi_spec(self, base_url: str, spec: Dict[str, Any]) -> List[APIEndpoint]:
        """Parse OpenAPI/Swagger specification"""
        endpoints = []
        
        # Get base path and server info
        base_path = spec.get('basePath', '')
        servers = spec.get('servers', [])
        
        if servers and 'url' in servers[0]:
            api_base = servers[0]['url']
        else:
            api_base = urljoin(base_url, base_path)
        
        # Parse paths
        paths = spec.get('paths', {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                    endpoint_url = urljoin(api_base, path.lstrip('/'))
                    
                    # Extract parameters
                    parameters = details.get('parameters', [])
                    path_params = [p['name'] for p in parameters if p.get('in') == 'path']
                    query_params = [p['name'] for p in parameters if p.get('in') == 'query']
                    
                    # Check for authentication requirements
                    auth_required = 'security' in details or 'security' in spec
                    
                    endpoint = APIEndpoint(
                        url=endpoint_url,
                        method=method.upper(),
                        path_params=path_params,
                        query_params=query_params,
                        auth_required=auth_required
                    )
                    endpoints.append(endpoint)
        
        return endpoints
    
    async def _discover_from_standard_files(self, base_url: str) -> List[APIEndpoint]:
        """Discover API endpoints from robots.txt and sitemap"""
        endpoints = []
        
        async with aiohttp.ClientSession() as session:
            # Check robots.txt
            try:
                robots_url = urljoin(base_url, '/robots.txt')
                async with session.get(robots_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        api_paths = self._extract_api_paths_from_text(content)
                        for path in api_paths:
                            endpoint = APIEndpoint(
                                url=urljoin(base_url, path),
                                method='GET'
                            )
                            endpoints.append(endpoint)
            except:
                pass
        
        return endpoints
    
    def _extract_api_paths_from_text(self, text: str) -> List[str]:
        """Extract API-like paths from text"""
        api_patterns = [
            r'/api/[^\s]+',
            r'/v\d+/[^\s]+',
            r'/graphql[^\s]*',
            r'/rest/[^\s]+',
            r'/service/[^\s]+'
        ]
        
        paths = []
        for pattern in api_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            paths.extend(matches)
        
        return list(set(paths))
    
    async def _discover_common_paths(self, base_url: str) -> List[APIEndpoint]:
        """Discover endpoints using common API paths"""
        common_paths = [
            '/api',
            '/api/v1',
            '/api/v2',
            '/rest',
            '/graphql',
            '/api/users',
            '/api/auth',
            '/api/login',
            '/api/admin',
            '/service',
            '/services',
            '/endpoints'
        ]
        
        endpoints = []
        
        async with aiohttp.ClientSession() as session:
            for path in common_paths:
                try:
                    url = urljoin(base_url, path)
                    async with session.get(url) as response:
                        if response.status in [200, 201, 400, 401, 403]:
                            endpoint = APIEndpoint(url=url, method='GET')
                            endpoints.append(endpoint)
                            
                            # Try other HTTP methods
                            for method in ['POST', 'PUT', 'DELETE']:
                                endpoint = APIEndpoint(url=url, method=method)
                                endpoints.append(endpoint)
                                
                except Exception as e:
                    continue
        
        return endpoints
    
    async def _discover_graphql(self, base_url: str) -> List[APIEndpoint]:
        """Discover GraphQL endpoints and perform introspection"""
        endpoints = []
        graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql', '/query']
        
        introspection_query = {
            "query": """
            query IntrospectionQuery {
              __schema {
                types {
                  name
                  fields {
                    name
                    type {
                      name
                    }
                  }
                }
              }
            }
            """
        }
        
        async with aiohttp.ClientSession() as session:
            for path in graphql_paths:
                try:
                    graphql_url = urljoin(base_url, path)
                    
                    # Test if GraphQL endpoint exists
                    async with session.post(graphql_url, json=introspection_query) as response:
                        if response.status == 200:
                            endpoint = APIEndpoint(
                                url=graphql_url,
                                method='POST',
                                headers={'Content-Type': 'application/json'}
                            )
                            endpoints.append(endpoint)
                            
                            # Try to get schema information
                            data = await response.json()
                            if 'data' in data and '__schema' in data['data']:
                                self.logger.info(f"GraphQL introspection successful at {graphql_url}")
                        
                except Exception as e:
                    continue
        
        return endpoints
    
    async def run_security_tests(self, endpoints: List[APIEndpoint], 
                                options: Dict[str, Any] = None) -> List[APITestResult]:
        """Run comprehensive security tests on API endpoints"""
        if options is None:
            options = {}
        
        all_results = []
        
        # Define test categories
        test_categories = {
            'authentication': self._test_authentication,
            'authorization': self._test_authorization,
            'injection': self._test_injection_vulnerabilities,
            'rate_limiting': self._test_rate_limiting,
            'data_exposure': self._test_data_exposure,
            'cors': self._test_cors_configuration,
            'input_validation': self._test_input_validation,
            'error_handling': self._test_error_handling
        }
        
        # Run selected tests
        selected_tests = options.get('tests', list(test_categories.keys()))
        
        for endpoint in endpoints:
            self.logger.info(f"Testing endpoint: {endpoint.method} {endpoint.url}")
            
            for test_name in selected_tests:
                if test_name in test_categories:
                    try:
                        test_func = test_categories[test_name]
                        result = await test_func(endpoint)
                        all_results.append(result)
                    except Exception as e:
                        self.logger.error(f"Error running {test_name} test: {e}")
        
        self.test_results = all_results
        return all_results
    
    async def _test_authentication(self, endpoint: APIEndpoint) -> APITestResult:
        """Test authentication mechanisms"""
        result = APITestResult('Authentication Test', endpoint)
        result.start_time = datetime.now()
        result.status = 'running'
        
        try:
            async with aiohttp.ClientSession() as session:
                # Test without authentication
                async with session.request(endpoint.method, endpoint.url) as response:
                    if response.status == 200:
                        result.add_finding(
                            "Endpoint accessible without authentication",
                            {
                                'status_code': response.status,
                                'endpoint': endpoint.url,
                                'method': endpoint.method
                            },
                            'high'
                        )
                    
                    # Test with invalid tokens
                    invalid_tokens = [
                        'Bearer invalid_token',
                        'Bearer ',
                        'Bearer null',
                        'Bearer undefined',
                        'invalid_token'
                    ]
                    
                    for token in invalid_tokens:
                        headers = {'Authorization': token}
                        async with session.request(endpoint.method, endpoint.url, headers=headers) as auth_response:
                            if auth_response.status == 200:
                                result.add_finding(
                                    f"Authentication bypass possible with invalid token: {token}",
                                    {
                                        'status_code': auth_response.status,
                                        'token': token
                                    },
                                    'critical'
                                )
                    
                    # Test JWT vulnerabilities if JWT is used
                    auth_header = response.headers.get('WWW-Authenticate', '')
                    if 'bearer' in auth_header.lower():
                        await self._test_jwt_vulnerabilities(result, endpoint, session)
            
            result.status = 'passed'
            
        except Exception as e:
            result.error = str(e)
            result.status = 'error'
        
        result.end_time = datetime.now()
        return result
    
    async def _test_jwt_vulnerabilities(self, result: APITestResult, endpoint: APIEndpoint, session):
        """Test JWT-specific vulnerabilities"""
        
        # Test algorithm confusion (alg: none)
        none_token = jwt.encode({}, None, algorithm=None)
        headers = {'Authorization': f'Bearer {none_token}'}
        
        async with session.request(endpoint.method, endpoint.url, headers=headers) as response:
            if response.status == 200:
                result.add_finding(
                    "JWT accepts 'none' algorithm",
                    {
                        'status_code': response.status,
                        'vulnerability': 'Algorithm confusion attack possible'
                    },
                    'critical'
                )
        
        # Test weak secret (common secrets)
        weak_secrets = ['secret', '123456', 'password', 'key', 'jwt']
        payload = {'user': 'admin', 'role': 'admin'}
        
        for secret in weak_secrets:
            try:
                weak_token = jwt.encode(payload, secret, algorithm='HS256')
                headers = {'Authorization': f'Bearer {weak_token}'}
                
                async with session.request(endpoint.method, endpoint.url, headers=headers) as response:
                    if response.status == 200:
                        result.add_finding(
                            f"JWT accepts weak secret: {secret}",
                            {
                                'status_code': response.status,
                                'secret': secret,
                                'vulnerability': 'Weak JWT secret'
                            },
                            'high'
                        )
            except:
                continue
    
    async def _test_authorization(self, endpoint: APIEndpoint) -> APITestResult:
        """Test authorization and access control"""
        result = APITestResult('Authorization Test', endpoint)
        result.start_time = datetime.now()
        result.status = 'running'
        
        try:
            async with aiohttp.ClientSession() as session:
                # Test privilege escalation through headers
                for bypass_headers in self.auth_bypass_headers:
                    async with session.request(endpoint.method, endpoint.url, headers=bypass_headers) as response:
                        if response.status == 200:
                            result.add_finding(
                                f"Authorization bypass possible with headers: {bypass_headers}",
                                {
                                    'status_code': response.status,
                                    'bypass_headers': bypass_headers
                                },
                                'high'
                            )
                
                # Test parameter pollution
                if endpoint.query_params:
                    for param in endpoint.query_params:
                        # Test array parameters
                        polluted_params = {
                            param: ['user', 'admin'],
                            f"{param}[]": 'admin'
                        }
                        
                        async with session.request(endpoint.method, endpoint.url, params=polluted_params) as response:
                            if response.status == 200:
                                result.add_finding(
                                    f"Parameter pollution possible with {param}",
                                    {
                                        'status_code': response.status,
                                        'parameter': param,
                                        'method': 'array_pollution'
                                    },
                                    'medium'
                                )
            
            result.status = 'passed'
            
        except Exception as e:
            result.error = str(e)
            result.status = 'error'
        
        result.end_time = datetime.now()
        return result
    
    async def _test_injection_vulnerabilities(self, endpoint: APIEndpoint) -> APITestResult:
        """Test for injection vulnerabilities"""
        result = APITestResult('Injection Test', endpoint)
        result.start_time = datetime.now()
        result.status = 'running'
        
        try:
            async with aiohttp.ClientSession() as session:
                # Test SQL injection
                for payload in self.sql_payloads:
                    # Test in query parameters
                    if endpoint.query_params:
                        for param in endpoint.query_params:
                            params = {param: payload}
                            async with session.request(endpoint.method, endpoint.url, params=params) as response:
                                response_text = await response.text()
                                if self._detect_sql_error(response_text):
                                    result.add_finding(
                                        f"SQL injection possible in parameter {param}",
                                        {
                                            'parameter': param,
                                            'payload': payload,
                                            'response_indicators': 'SQL error detected'
                                        },
                                        'critical'
                                    )
                    
                    # Test in JSON body
                    if endpoint.method in ['POST', 'PUT', 'PATCH']:
                        json_payload = {'test': payload}
                        try:
                            async with session.request(endpoint.method, endpoint.url, json=json_payload) as response:
                                response_text = await response.text()
                                if self._detect_sql_error(response_text):
                                    result.add_finding(
                                        "SQL injection possible in JSON body",
                                        {
                                            'payload': payload,
                                            'response_indicators': 'SQL error detected'
                                        },
                                        'critical'
                                    )
                        except:
                            pass
                
                # Test XSS
                for payload in self.xss_payloads:
                    if endpoint.query_params:
                        for param in endpoint.query_params:
                            params = {param: payload}
                            async with session.request(endpoint.method, endpoint.url, params=params) as response:
                                response_text = await response.text()
                                if payload in response_text and 'script' in response_text:
                                    result.add_finding(
                                        f"XSS possible in parameter {param}",
                                        {
                                            'parameter': param,
                                            'payload': payload
                                        },
                                        'high'
                                    )
                
                # Test XXE (for XML endpoints)
                if endpoint.method in ['POST', 'PUT', 'PATCH']:
                    for xxe_payload in self.xxe_payloads:
                        headers = {'Content-Type': 'application/xml'}
                        try:
                            async with session.request(endpoint.method, endpoint.url, 
                                                     data=xxe_payload, headers=headers) as response:
                                response_text = await response.text()
                                if 'root:' in response_text or 'daemon:' in response_text:
                                    result.add_finding(
                                        "XXE vulnerability detected",
                                        {
                                            'payload': xxe_payload,
                                            'response_indicators': 'System file content detected'
                                        },
                                        'critical'
                                    )
                        except:
                            pass
            
            result.status = 'passed'
            
        except Exception as e:
            result.error = str(e)
            result.status = 'error'
        
        result.end_time = datetime.now()
        return result
    
    def _detect_sql_error(self, response_text: str) -> bool:
        """Detect SQL error messages in response"""
        sql_errors = [
            'sql syntax',
            'mysql_fetch',
            'ora-\d+',
            'microsoft ole db',
            'sqlite_',
            'postgresql',
            'syntax error',
            'unclosed quotation mark',
            'quoted string not properly terminated'
        ]
        
        response_lower = response_text.lower()
        return any(re.search(error, response_lower) for error in sql_errors)
    
    async def _test_rate_limiting(self, endpoint: APIEndpoint) -> APITestResult:
        """Test rate limiting implementation"""
        result = APITestResult('Rate Limiting Test', endpoint)
        result.start_time = datetime.now()
        result.status = 'running'
        
        try:
            requests_count = 100
            success_count = 0
            
            async with aiohttp.ClientSession() as session:
                tasks = []
                for i in range(requests_count):
                    task = self._make_request(session, endpoint)
                    tasks.append(task)
                
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                for response in responses:
                    if isinstance(response, tuple) and response[0] == 200:
                        success_count += 1
                
                # If more than 80% of requests succeed, rate limiting might be weak
                success_rate = success_count / requests_count
                if success_rate > 0.8:
                    result.add_finding(
                        f"Weak or missing rate limiting (Success rate: {success_rate:.2%})",
                        {
                            'total_requests': requests_count,
                            'successful_requests': success_count,
                            'success_rate': success_rate
                        },
                        'medium'
                    )
            
            result.status = 'passed'
            
        except Exception as e:
            result.error = str(e)
            result.status = 'error'
        
        result.end_time = datetime.now()
        return result
    
    async def _make_request(self, session: aiohttp.ClientSession, endpoint: APIEndpoint) -> Tuple[int, str]:
        """Make a single request and return status code and response"""
        try:
            async with session.request(endpoint.method, endpoint.url) as response:
                return (response.status, await response.text())
        except Exception:
            return (0, "")
    
    async def _test_data_exposure(self, endpoint: APIEndpoint) -> APITestResult:
        """Test for sensitive data exposure"""
        result = APITestResult('Data Exposure Test', endpoint)
        result.start_time = datetime.now()
        result.status = 'running'
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(endpoint.method, endpoint.url) as response:
                    response_text = await response.text()
                    headers = dict(response.headers)
                    
                    # Check for sensitive information in response
                    sensitive_patterns = {
                        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                        'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
                        'ssn': r'\b\d{3}-?\d{2}-?\d{4}\b',
                        'api_key': r'["\']?(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?[\w-]+["\']?',
                        'password': r'["\']?password["\']?\s*[:=]\s*["\']?[^"\'\s]+["\']?',
                        'secret': r'["\']?(?:secret|token)["\']?\s*[:=]\s*["\']?[\w-]+["\']?'
                    }
                    
                    for pattern_name, pattern in sensitive_patterns.items():
                        matches = re.findall(pattern, response_text, re.IGNORECASE)
                        if matches:
                            result.add_finding(
                                f"Potential {pattern_name} exposure in response",
                                {
                                    'pattern': pattern_name,
                                    'matches_count': len(matches),
                                    'sample_matches': matches[:3]  # First 3 matches
                                },
                                'high'
                            )
                    
                    # Check response headers for information disclosure
                    sensitive_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
                    for header in sensitive_headers:
                        if header in headers:
                            result.add_finding(
                                f"Information disclosure in {header} header",
                                {
                                    'header': header,
                                    'value': headers[header]
                                },
                                'low'
                            )
            
            result.status = 'passed'
            
        except Exception as e:
            result.error = str(e)
            result.status = 'error'
        
        result.end_time = datetime.now()
        return result
    
    async def _test_cors_configuration(self, endpoint: APIEndpoint) -> APITestResult:
        """Test CORS configuration"""
        result = APITestResult('CORS Test', endpoint)
        result.start_time = datetime.now()
        result.status = 'running'
        
        try:
            async with aiohttp.ClientSession() as session:
                # Test CORS with different origins
                test_origins = [
                    'http://evil.com',
                    'https://attacker.com',
                    'null',
                    'http://localhost:3000'
                ]
                
                for origin in test_origins:
                    headers = {
                        'Origin': origin,
                        'Access-Control-Request-Method': endpoint.method,
                        'Access-Control-Request-Headers': 'Content-Type'
                    }
                    
                    # Preflight request
                    async with session.options(endpoint.url, headers=headers) as response:
                        cors_headers = dict(response.headers)
                        
                        allowed_origin = cors_headers.get('Access-Control-Allow-Origin')
                        if allowed_origin == '*':
                            result.add_finding(
                                "CORS allows all origins (*)",
                                {
                                    'allowed_origin': allowed_origin,
                                    'risk': 'Potential for cross-origin attacks'
                                },
                                'medium'
                            )
                        elif allowed_origin == origin and origin in ['http://evil.com', 'https://attacker.com']:
                            result.add_finding(
                                f"CORS allows potentially malicious origin: {origin}",
                                {
                                    'allowed_origin': allowed_origin,
                                    'test_origin': origin
                                },
                                'high'
                            )
                        
                        # Check for credentials allowed with wildcard
                        if (allowed_origin == '*' and 
                            cors_headers.get('Access-Control-Allow-Credentials') == 'true'):
                            result.add_finding(
                                "CORS allows credentials with wildcard origin",
                                {
                                    'vulnerability': 'Credentials can be sent from any origin'
                                },
                                'critical'
                            )
            
            result.status = 'passed'
            
        except Exception as e:
            result.error = str(e)
            result.status = 'error'
        
        result.end_time = datetime.now()
        return result
    
    async def _test_input_validation(self, endpoint: APIEndpoint) -> APITestResult:
        """Test input validation"""
        result = APITestResult('Input Validation Test', endpoint)
        result.start_time = datetime.now()
        result.status = 'running'
        
        # Test various malformed inputs
        malformed_inputs = [
            {'test': 'a' * 10000},  # Very long string
            {'test': -999999999},   # Large negative number
            {'test': 999999999999999999999},  # Very large number
            {'test': None},         # Null value
            {'test': []},           # Empty array
            {'test': {}},           # Empty object
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                for malformed_input in malformed_inputs:
                    if endpoint.method in ['POST', 'PUT', 'PATCH']:
                        try:
                            async with session.request(endpoint.method, endpoint.url, 
                                                     json=malformed_input) as response:
                                if response.status == 500:
                                    response_text = await response.text()
                                    result.add_finding(
                                        f"Server error with malformed input: {malformed_input}",
                                        {
                                            'input': str(malformed_input)[:100],
                                            'status_code': response.status,
                                            'error_indication': 'Server error suggests poor input validation'
                                        },
                                        'medium'
                                    )
                        except:
                            pass
            
            result.status = 'passed'
            
        except Exception as e:
            result.error = str(e)
            result.status = 'error'
        
        result.end_time = datetime.now()
        return result
    
    async def _test_error_handling(self, endpoint: APIEndpoint) -> APITestResult:
        """Test error handling and information disclosure"""
        result = APITestResult('Error Handling Test', endpoint)
        result.start_time = datetime.now()
        result.status = 'running'
        
        try:
            async with aiohttp.ClientSession() as session:
                # Test with malformed requests
                error_tests = [
                    {'method': endpoint.method, 'url': endpoint.url + '/../../../etc/passwd'},
                    {'method': endpoint.method, 'url': endpoint.url, 'headers': {'Content-Type': 'invalid/type'}},
                    {'method': endpoint.method, 'url': endpoint.url, 'data': 'invalid json'},
                ]
                
                for test in error_tests:
                    try:
                        async with session.request(**test) as response:
                            if response.status >= 500:
                                response_text = await response.text()
                                
                                # Check for stack traces
                                if any(indicator in response_text.lower() for indicator in 
                                      ['traceback', 'stack trace', 'exception', 'error at line']):
                                    result.add_finding(
                                        "Error response contains stack trace information",
                                        {
                                            'status_code': response.status,
                                            'indication': 'Stack trace or debug information exposed'
                                        },
                                        'medium'
                                    )
                                
                                # Check for database errors
                                if self._detect_sql_error(response_text):
                                    result.add_finding(
                                        "Database error information disclosed",
                                        {
                                            'status_code': response.status,
                                            'indication': 'Database error details exposed'
                                        },
                                        'low'
                                    )
                    except:
                        pass
            
            result.status = 'passed'
            
        except Exception as e:
            result.error = str(e)
            result.status = 'error'
        
        result.end_time = datetime.now()
        return result
    
    def get_test_summary(self) -> Dict[str, Any]:
        """Get summary of all test results"""
        if not self.test_results:
            return {}
        
        summary = {
            'total_tests': len(self.test_results),
            'passed': 0,
            'failed': 0,
            'error': 0,
            'severity_counts': {'info': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
            'total_findings': 0,
            'unique_endpoints': set(),
            'test_categories': {}
        }
        
        for result in self.test_results:
            # Count by status
            summary[result.status] = summary.get(result.status, 0) + 1
            
            # Count by severity
            summary['severity_counts'][result.severity] += 1
            
            # Count findings
            summary['total_findings'] += len(result.findings)
            
            # Track unique endpoints
            summary['unique_endpoints'].add(f"{result.endpoint.method} {result.endpoint.url}")
            
            # Count by test category
            test_category = result.test_name.replace(' Test', '').lower()
            summary['test_categories'][test_category] = summary['test_categories'].get(test_category, 0) + 1
        
        summary['unique_endpoints'] = len(summary['unique_endpoints'])
        
        return summary