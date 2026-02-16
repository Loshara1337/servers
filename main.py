import yaml
import urllib.parse
import base64
import sys

# Настройки имен файлов
INPUT_FILE = 'links.txt'
OUTPUT_FILE = 'config.yaml'

def safe_base64_decode(s):
    """Декодирует base64, даже если нет паддинга (=)"""
    s = s.strip()
    # Восстанавливаем паддинг
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    try:
        return base64.urlsafe_b64decode(s).decode('utf-8', errors='ignore')
    except:
        return s

def parse_vless(url_str):
    """Парсит vless ссылку и возвращает словарь прокси для Clash"""
    try:
        parsed = urllib.parse.urlparse(url_str)
        if parsed.scheme != 'vless':
            return None
        
        # Извлекаем параметры из query string
        params = urllib.parse.parse_qs(parsed.query)
        # parse_qs возвращает списки {'key': ['val']}, берем первые значения
        q = {k: v[0] for k, v in params.items()}
        
        # Базовая структура
        proxy = {
            'name': urllib.parse.unquote(parsed.fragment) or parsed.hostname,
            'type': 'vless',
            'server': parsed.hostname,
            'port': parsed.port,
            'uuid': parsed.username,
            'udp': True,
            'tls': True,
            'network': q.get('type', 'tcp'),
            'servername': q.get('sni', ''),
            'client-fingerprint': q.get('fp', 'chrome')
        }

        # Проверка на Reality (security=reality или наличие pbk)
        is_reality = q.get('security') == 'reality' or 'pbk' in q
        
        if not is_reality:
            return None # Нам нужны только Reality, как в ТЗ

        # Настройки Reality
        proxy['reality-opts'] = {
            'public-key': q.get('pbk', ''),
            'short-id': q.get('sid', '')
        }
        
        # Дополнительные настройки сети (grpc, ws и т.д.)
        net = proxy['network']
        if net == 'grpc':
            proxy['grpc-opts'] = {
                'grpc-service-name': q.get('serviceName', '')
            }
        elif net == 'ws':
            proxy['ws-opts'] = {
                'path': q.get('path', '/'),
                'headers': {'Host': q.get('host', parsed.hostname)}
            }
        
        # Flow (важно для Reality Vision)
        if 'flow' in q:
            proxy['flow'] = q['flow']

        return proxy
    except Exception as e:
        print(f"Error parsing link: {e}")
        return None

def main():
    proxies = []
    
    # 1. Чтение файла
    try:
        with open(INPUT_FILE, 'r', encoding='utf-8') as f:
            content = f.read().strip()
    except FileNotFoundError:
        print(f"File {INPUT_FILE} not found.")
        return

    # 2. Обработка контента (если это одна большая base64 строка или список ссылок)
    # Попробуем декодировать весь файл, если он выглядит как base64
    if "://" not in content and len(content) > 10:
        decoded = safe_base64_decode(content)
        if "://" in decoded:
            content = decoded

    lines = content.splitlines()

    # 3. Парсинг
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # Если ссылка vless
        if line.startswith('vless://'):
            proxy = parse_vless(line)
            if proxy:
                # Уникальное имя (чтобы Mihomo не ругался)
                while any(p['name'] == proxy['name'] for p in proxies):
                    proxy['name'] += "_1"
                proxies.append(proxy)

    if not proxies:
        print("No Reality proxies found.")
        # Можно создать пустой файл или выйти, чтобы не ломать конфиг
        # sys.exit(1) 

    # 4. Генерация структуры конфига Mihomo / Clash
    proxy_names = [p['name'] for p in proxies]
    
    config = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': True,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'proxies': proxies,
        'proxy-groups': [
            {
                'name': 'Auto-Select',
                'type': 'url-test',
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300,
                'tolerance': 50,
                'proxies': proxy_names
            },
            {
                'name': 'Reality-Only',
                'type': 'select',
                'proxies': ['Auto-Select'] + proxy_names
            },
             {
                'name': 'Final',
                'type': 'select',
                'proxies': ['Reality-Only', 'DIRECT']
            }
        ],
        'rules': [
            'GEOIP,CN,DIRECT',
            'MATCH,Final'
        ]
    }

    # 5. Сохранение в YAML
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        # allow_unicode=True чтобы русские названия прокси не превращались в кракозябры
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    
    print(f"Config generated with {len(proxies)} proxies.")

if __name__ == "__main__":
    main()
