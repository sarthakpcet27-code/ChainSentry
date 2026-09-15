readme = open('readme_content.txt', 'r', encoding='utf-8').read()
with open('readme.md', 'w', encoding='utf-8') as f:
    f.write(readme)
print('done', len(readme))
