import json
import requests
from datetime import datetime, timezone
import os

CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'projects_overview_config.json')
OUTPUT_HTML = os.path.abspath(os.path.join(os.path.dirname(__file__), '../projects/projects_overview.html'))


def load_config():
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)

def fetch_projects(api_url):
    resp = requests.get(api_url)
    resp.raise_for_status()
    return resp.json()['data']['projects']

def extract_versions(projects, prefix):
    # Find all project keys that start with the prefix and extract the version part
    filtered = [k for k in projects if k.startswith(prefix)]
    # Extract version numbers for sorting
    def version_key(name):
        # e.g., windows-ld-v-2-3-x -> [2, 3]
        parts = name[len(prefix):].split('-')
        nums = [int(p) for p in parts if p.isdigit()]
        return nums
    filtered.sort(key=version_key, reverse=True)
    return filtered

def build_html(groups, projects):
    html = ['<!DOCTYPE html>', '<html lang="en">', '<head>',
            '<meta charset="UTF-8">', '<title>Allure Projects Overview</title>',
            '<style>body{font-family:sans-serif;} .group{margin-bottom:2em;} h2{margin-bottom:0.5em;} ul{list-style:disc;margin-left:2em;}</style>',
            '</head>', '<body>']
    html.append('<h1>Allure Projects Overview</h1>')
    for group in groups:
        header = group['header']
        prefix = group['prefix']
        count = group.get('count', 2)
        html.append(f'<div class="group"><h2>{header}</h2><ul>')
        versions = extract_versions(projects, prefix)[:count]
        for v in versions:
            url = f"{projects[v]['uri']}/reports/latest/index.html"
            html.append(f'<li><a href="{url}" target="_blank">{v}</a></li>')
        html.append('</ul></div>')
    # Footer with UTC timestamp
    now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    html.append(f'<footer><hr><div style="font-size:small;">Last generated: {now_utc}</div></footer>')
    html.append('</body></html>')
    return '\n'.join(html)

def main():
    config = load_config()
    projects = fetch_projects(config['projects_api_url'])
    html = build_html(config['groups'], projects)
    with open(OUTPUT_HTML, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"Projects overview HTML generated at {OUTPUT_HTML}")

if __name__ == '__main__':
    main()
