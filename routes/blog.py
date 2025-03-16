from flask import Flask, render_template, redirect, url_for, request, flash, session, send_from_directory, Blueprint
from helpers import *
from config import *

import os
import markdown

blog_bp = Blueprint('blog', __name__)

@blog_bp.route('/articles')
def list_articles():
    articles = []
    if not os.path.exists(ARTICLES_DIR):
        os.makedirs(ARTICLES_DIR) # if the articles folder doesn't exist, make it

    for filename in os.listdir(ARTICLES_DIR):
        if filename.endswith('.md'):
            slug = filename[:-3] # the URL slug should just be the filename (removing .md extension)
            articles.append({'title': slug.replace('-', ' ').title(), 'slug': slug}) # adding the slug to articles list with jproper format

    return render_template('articles.html', articles=sorted(articles, key=lambda x: x['title'])) # lambda functions rule!!!
    
# Rendering an individal article
@blog_bp.route('/articles/<slug>')
def view_article(slug):
    article_path = os.path.join(ARTICLES_DIR, f'{slug}.md')

    if not os.path.exists(article_path):
        flash('File not found', 'error')
        return redirect(url_for('dashboard'))

    # thanks, StackOverflow!!
    with open(article_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # converting the markdown to HTML
    html_content = markdown.markdown(content)

    return render_template('view_article.html', title=slug.replace('-', ' ').title(), content=html_content)