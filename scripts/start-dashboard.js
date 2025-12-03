// scripts/start-dashboard.js

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const http = require('http');
const url = require('url');

const PORT = 3000;
const VITEST_UI_PORT = 51204;

console.log('🎯 NSTech Corporate Auth Policies - Test Dashboard');
console.log('='.repeat(50));
console.log('\n🚀 Iniciando servidores...\n');

// Start Vitest UI
console.log('1. Iniciando Vitest UI...');
const vitest = spawn('npx', ['vitest', '--ui'], {
    stdio: 'pipe',
    shell: true
});

vitest.stdout.on('data', (data) => {
    console.log(`[Vitest UI] ${data.toString().trim()}`);
});

vitest.stderr.on('data', (data) => {
    console.error(`[Vitest UI Error] ${data.toString().trim()}`);
});

vitest.on('error', (error) => {
    console.error('❌ Erro ao iniciar Vitest UI:', error);
});

vitest.on('close', (code) => {
    console.log(`📤 Vitest UI encerrado com código: ${code}`);
});

// Wait for Vitest UI to start
setTimeout(() => {
    console.log('2. Iniciando Dashboard...');
    
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '/');
        const filePath = parsedUrl.pathname === '/' ? '/ui-welcome.html' : parsedUrl.pathname;
        
        // Serve static files from tests directory
        const fullPath = path.join(__dirname, '..', 'tests', filePath);
        
        fs.readFile(fullPath, (err, content) => {
            if (err) {
                if (err.code === 'ENOENT') {
                    // Serve default page if file not found
                    res.writeHead(200, { 'Content-Type': 'text/html' });
                    res.end(`
                        <html>
                            <head>
                                <title>NSTech Test Dashboard</title>
                                <style>
                                    body {
                                        font-family: 'Inter', sans-serif;
                                        background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
                                        min-height: 100vh;
                                        display: flex;
                                        align-items: center;
                                        justify-content: center;
                                        margin: 0;
                                    }
                                    .container {
                                        text-align: center;
                                        padding: 40px;
                                        background: white;
                                        border-radius: 20px;
                                        box-shadow: 0 10px 25px rgba(0,0,0,0.1);
                                    }
                                    h1 {
                                        color: #1e293b;
                                        margin-bottom: 20px;
                                    }
                                    .links {
                                        display: flex;
                                        gap: 15px;
                                        justify-content: center;
                                        margin-top: 30px;
                                    }
                                    .link {
                                        padding: 12px 24px;
                                        background: #3b82f6;
                                        color: white;
                                        text-decoration: none;
                                        border-radius: 10px;
                                        font-weight: 600;
                                        transition: transform 0.3s;
                                    }
                                    .link:hover {
                                        transform: translateY(-2px);
                                    }
                                </style>
                            </head>
                            <body>
                                <div class="container">
                                    <h1>🚀 NSTech Test Dashboard</h1>
                                    <p>Dashboard de testes para Corporate Auth Policies</p>
                                    <div class="links">
                                        <a href="http://localhost:${VITEST_UI_PORT}/__vitest__/" class="link" target="_blank">
                                            Abrir Vitest UI
                                        </a>
                                        <a href="/" class="link">
                                            Recarregar Dashboard
                                        </a>
                                    </div>
                                </div>
                            </body>
                        </html>
                    `);
                } else {
                    res.writeHead(500);
                    res.end('Server Error');
                }
            } else {
                // Determine content type
                const extname = path.extname(fullPath);
                let contentType = 'text/html';
                
                switch (extname) {
                    case '.js':
                        contentType = 'text/javascript';
                        break;
                    case '.css':
                        contentType = 'text/css';
                        break;
                    case '.json':
                        contentType = 'application/json';
                        break;
                    case '.png':
                        contentType = 'image/png';
                        break;
                    case '.jpg':
                        contentType = 'image/jpg';
                        break;
                    case '.ttf':
                        contentType = 'font/ttf';
                        break;
                }
                
                res.writeHead(200, { 'Content-Type': contentType });
                res.end(content);
            }
        });
    });

    server.listen(PORT, () => {
        console.log(`\n✅ Servidores iniciados com sucesso!\n`);
        console.log('📋 URLs disponíveis:');
        console.log(`   • Dashboard:      http://localhost:${PORT}`);
        console.log(`   • Vitest UI:      http://localhost:${VITEST_UI_PORT}/__vitest__/`);
        console.log(`   • Cobertura:      file://${path.join(process.cwd(), 'coverage/index.html')}`);
        console.log('\n⚡ Comandos disponíveis:');
        console.log('   • Audience:       npm run test:audience');
        console.log('   • Roles:          npm run test:role');
        console.log('   • Todos:          npm run test:coverage');
        console.log('   • Watch:          npm run test:watch');
        console.log('\n🛑 Pressione Ctrl+C para encerrar\n');
    });

    // Handle shutdown
    process.on('SIGINT', () => {
        console.log('\n\n👋 Encerrando servidores...');
        vitest.kill();
        server.close();
        process.exit(0);
    });

}, 3000);