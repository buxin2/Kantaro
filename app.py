from flask import Flask
import os

app = Flask(__name__)

@app.route('/')
def home():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>🔒 AI Security Camera System</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
            .hero { padding: 100px 0; color: white; text-align: center; }
        </style>
    </head>
    <body>
        <div class="hero">
            <div class="container">
                <h1 class="display-1">🔒 AI Security Camera System</h1>
                <p class="lead">Enterprise AI-powered security monitoring platform</p>
                <h3>✅ Successfully Deployed on Render!</h3>
                <div class="mt-5">
                    <div class="row">
                        <div class="col-md-4">
                            <div class="card">
                                <div class="card-body">
                                    <h4>🤖 AI Detection</h4>
                                    <p>YOLOv8 object detection with real-time processing</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card">
                                <div class="card-body">
                                    <h4>📹 Multi-Camera</h4>
                                    <p>Support for IP cameras and device cameras</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card">
                                <div class="card-body">
                                    <h4>☁️ Cloud Ready</h4>
                                    <p>Scalable deployment with authentication</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/health')
def health():
    return {'status': 'healthy', 'message': 'AI Security Camera System Demo'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
