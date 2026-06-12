import base64

with open(r'c:\Users\smgal\Documents\harvestX\live_monitor\logo.png', 'rb') as f:
    b64 = base64.b64encode(f.read()).decode('utf-8')

html_path = r'c:\Users\smgal\Documents\harvestX\live_monitor\index.html'
with open(html_path, 'r', encoding='utf-8') as f:
    html = f.read()

html = html.replace('src="logo.png"', 'src="data:image/png;base64,' + b64 + '"')

with open(html_path, 'w', encoding='utf-8') as f:
    f.write(html)

print('Embedded base64 logo in live_monitor/index.html')
