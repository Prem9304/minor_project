from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import re
import json
import os
from groq import Groq
import xml.etree.ElementTree as ET

app = Flask(__name__)
CORS(app)

# Initialize Groq client with error handling
def init_groq_client():
    try:
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            print("Warning: GROQ_API_KEY environment variable not set")
            return None
        return Groq(api_key=api_key)
    except Exception as e:
        print(f"Error initializing Groq client: {str(e)}")
        return None

# Initialize Groq client
client = init_groq_client()

def check_privileges():
    """Check if script has root privileges"""
    return os.geteuid() == 0

def sanitize_ip(ip):
    """Validate and sanitize IP address input."""
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$|^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$')
    if not ip_pattern.match(ip):
        return None
    return ip

def run_nmap_scan(ip, scan_type):
    """Run Nmap scan with specified parameters."""
    try:
        # Validate scan type
        valid_scan_types = ['syn', 'udp', 'os']
        if scan_type not in valid_scan_types:
            return {
                'success': False,
                'error': f'Invalid scan type. Must be one of: {", ".join(valid_scan_types)}'
            }

        # Define command based on scan type
        if scan_type == 'syn':
            command = ['nmap', '-sS', '-sV', '-oX', '-', ip]
        elif scan_type == 'udp':
            command = ['nmap', '-sU', '--top-ports', '100', '-oX', '-', ip]
        elif scan_type == 'os':
            command = ['nmap', '-O', '-sV', '-oX', '-', ip]

        # Run the scan
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )

        return {
            'success': True,
            'output': process.stdout,
            'command': ' '.join(command)
        }
    except subprocess.CalledProcessError as e:
        return {
            'success': False,
            'error': f'Nmap scan failed: {str(e.stderr)}',
            'command': ' '.join(command)
        }
    except Exception as e:
        return {
            'success': False,
            'error': f'Unexpected error: {str(e)}',
            'command': ' '.join(command) if 'command' in locals() else 'Command not executed'
        }

def analyze_scan_with_groq(scan_data):
    """Analyze network scan results using Groq AI."""
    if client is None:
        return {
            'success': False,
            'error': 'Groq AI client not initialized'
        }

    try:
        prompt = f"""As a security analyst, analyze this network scan result and provide a detailed analysis in HTML format. Use the following structure and formatting guidelines:

<div class="security-analysis">
    <div class="section mb-4">
        <h4 class="text-primary mb-3">🎯 Security Assessment</h4>
        <p class="mb-3">
            [Provide overall risk assessment with proper paragraph breaks]
        </p>
        <ul class="mb-3">
            [Key findings as bullet points]
        </ul>
    </div>

    <div class="section mb-4">
        <h4 class="text-warning mb-3">⚠️ Potential Vulnerabilities</h4>
        <ul class="mb-3">
            <li class="mb-2">
                <strong>[Vulnerability Name]</strong>
                <p class="mt-2">[Detailed explanation with proper line breaks]</p>
                {{% if there's related code or command %}}
                <pre class="bg-light p-3 mt-2 mb-2 rounded"><code>[Related code or command]</code></pre>
                {{% endif %}}
            </li>
            [Repeat for each vulnerability]
        </ul>
    </div>

    <div class="section mb-4">
        <h4 class="text-success mb-3">💡 Security Recommendations</h4>
        <ol class="mb-3">
            <li class="mb-2">
                <strong>[Recommendation Title]</strong>
                <p class="mt-2">[Detailed explanation]</p>
                {{% if there's an example command or configuration %}}
                <pre class="bg-light p-3 mt-2 mb-2 rounded"><code>[Example command or configuration]</code></pre>
                {{% endif %}}
            </li>
            [Repeat for each recommendation]
        </ol>
    </div>

    <div class="section mb-4">
        <h4 class="text-info mb-3">🔍 Notable Findings</h4>
        <ul class="mb-3">
            <li class="mb-2">
                <strong>[Finding Title]</strong>
                <p class="mt-2">[Detailed explanation]</p>
                {{% if there's relevant output %}}
                <pre class="bg-light p-3 mt-2 mb-2 rounded"><code>[Relevant output or command]</code></pre>
                {{% endif %}}
            </li>
            [Repeat for each finding]
        </ul>
    </div>
    
    <div class="section mb-4">
        <h4 class="text-danger mb-3">💻 Metasploit Code Snippets</h4>
        <ul class="mb-3">
            <li class="mb-2">
                <strong>[Exploit Title]</strong>
                <p class="mt-2">[Description of the exploit or module]</p>
                {{% if there’s relevant Metasploit code %}}
                <pre class="bg-dark text-light p-3 mt-2 mb-2 rounded"><code>[Metasploit commands or Ruby code]</code></pre>
                {{% endif %}}
            </li>
            [Repeat for each code snippet]
        </ul>
</div>

</div>

Scan data: {json.dumps(scan_data, indent=2)}

Important formatting rules:
1. Use <p> tags with proper margin classes (mb-3, mt-2) for paragraphs
2. Always wrap code, commands, and technical output in <pre><code> tags with proper styling
3. Use <strong> tags for headers and important terms
4. Maintain proper spacing between sections using mb-4 class
5. Use proper list structure with mb-2 class for list items
6. Each major point should have its own paragraph
7. Use proper indentation in code blocks
8. Include specific commands or configurations where relevant
9. Technical details should be formatted as code when appropriate

Remember to:
1. Replace all placeholder text in brackets
2. Keep the HTML structure intact
3. Ensure all code snippets are properly formatted
4. Use detailed explanations with proper paragraph breaks
5. Make all recommendations specific and actionable"""

        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": """You are a cybersecurity analyst focused on defensive security and risk mitigation. 
                    Provide detailed analysis in HTML format with proper structure and formatting.
                    Always use proper paragraph breaks (<p> tags) for readability.
                    Format all technical content (commands, configurations, outputs) using <pre><code> tags."""
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.3
        )
        
        return {
            'success': True,
            'analysis': chat_completion.choices[0].message.content
        }
    except Exception as e:
        return {
            'success': False,
            'error': f'AI analysis failed: {str(e)}'
        }


@app.route('/api/status', methods=['GET'])
def get_status():
    try:
        # Check if nmap is available
        subprocess.run(['nmap', '--version'], capture_output=True, check=True)
        
        # Check if we have root privileges
        has_root = check_privileges()
        
        # Check if Groq API is configured
        groq_available = os.environ.get("GROQ_API_KEY") is not None
        
        return jsonify({
            'running': True,
            'nmap_available': True,
            'root_privileges': has_root,
            'groq_available': groq_available
        })
    except subprocess.CalledProcessError:
        return jsonify({
            'running': True,
            'nmap_available': False,
            'root_privileges': check_privileges(),
            'groq_available': os.environ.get("GROQ_API_KEY") is not None
        })
    except Exception as e:
        return jsonify({
            'running': True,
            'error': str(e)
        })

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    
    if not data or 'ip' not in data or 'scanType' not in data:
        return jsonify({
            'success': False,
            'error': 'Missing required parameters'
        })
    
    # Sanitize IP address
    ip = sanitize_ip(data['ip'])
    if not ip:
        return jsonify({
            'success': False,
            'error': 'Invalid IP address or hostname'
        })
    
    # Run the scan
    scan_result = run_nmap_scan(ip, data['scanType'])
    
    if scan_result['success']:
        # Get AI analysis if scan was successful
        ai_result = analyze_scan_with_groq(scan_result['output'])
        
        return jsonify({
            'success': True,
            'command': scan_result['command'],
            'raw_results': scan_result['output'],
            'ai_analysis': ai_result
        })
    else:
        return jsonify({
            'success': False,
            'error': scan_result['error'],
            'command': scan_result.get('command')
        })

if __name__ == '__main__':
    print("Starting Cybersecurity Scanner Backend...")
    print("Checking prerequisites...")
    
    # Check environment variables
    if not os.environ.get("GROQ_API_KEY"):
        print("Warning: GROQ_API_KEY environment variable not set")
        print("AI analysis features will be disabled")
    
    # Check root privileges
    has_root = check_privileges()
    if not has_root:
        print("Warning: Application requires root privileges for full functionality")
        print("Please run with sudo")
    
    # Check for nmap installation
    try:
        nmap_version = subprocess.check_output(['nmap', '--version'], text=True).split('\n')[0]
        print(f"Found {nmap_version}")
    except:
        print("Error: Nmap not found. Please install nmap")
        print("On Kali Linux, run: sudo apt-get install nmap")
        exit(1)
    
    print("\nStarting server on http://0.0.0.0:5000")
    try:
        app.run(host='0.0.0.0', port=5000, debug=True)
    except Exception as e:
        print(f"Error starting server: {str(e)}")