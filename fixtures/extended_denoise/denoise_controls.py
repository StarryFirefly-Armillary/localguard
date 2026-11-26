# ARTIFICIAL STATIC FIXTURE - DO NOT EXECUTE, import, or install dependencies.
# Names and data are inert examples; findings are rule matches, not exploit proof.
import hashlib
import os
import random
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from jinja2 import Environment
from lxml import etree

# --- weak-crypto-random: true positives (all six calls must stay detectable) ---
def random_security_calls():
    # ruleid: lg.ext.weak-crypto-random
    a = random.randint(1, 100)
    # ruleid: lg.ext.weak-crypto-random
    b = random.random()
    # ruleid: lg.ext.weak-crypto-random
    c = random.choice("abc")
    # ruleid: lg.ext.weak-crypto-random
    d = random.choices("abc")
    # ruleid: lg.ext.weak-crypto-random
    e = random.sample("abc", 2)
    # ruleid: lg.ext.weak-crypto-random
    random.shuffle([1, 2, 3])

def random_backoff(jitter):
    # ok: lg.ext.weak-crypto-random
    return random.random() * jitter

# --- weak-crypto-sha1 ---
def sha1_password(password):
    # ruleid: lg.ext.weak-crypto-sha1
    return hashlib.sha1(password.encode()).hexdigest()

def sha1_non_security(s):
    # ok: lg.ext.weak-crypto-sha1
    return hashlib.sha1(s, usedforsecurity=False).hexdigest()

def get_template_key(name):
    # ok: lg.ext.weak-crypto-sha1
    return hashlib.sha1(name.encode()).hexdigest()

# --- eval/exec/compile ---
def eval_unsafe(request):
    # ruleid: lg.ext.code-injection-eval-exec
    return eval(request.args.get("expr"))

def eval_compile_unsafe(request):
    code = request.args.get("code")
    # ruleid: lg.ext.code-injection-eval-exec
    return compile(code, "<s>", "exec")

def eval_config_get_unsafe(user_key):
    # ruleid: lg.ext.code-injection-eval-exec
    return eval(CONFIG.get(user_key))

def eval_fixed_literal():
    # ok: lg.ext.code-injection-eval-exec
    return eval("1+1")

def eval_allowlisted(request):
    allowed = {"a": "1+1"}
    # ok: lg.ext.code-injection-eval-exec
    return eval(allowed.get(request.args.get("k", "a"), "1+1"))

# --- xxe-lxml-etree ---
def xxe_unsafe(request):
    # ruleid: lg.ext.xxe-lxml-etree
    return etree.fromstring(request.body)

def xxe_dangerous_parser(request):
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True)
    # ruleid: lg.ext.xxe-lxml-etree
    return etree.fromstring(request.body, parser)

def xxe_safe_parser(request):
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    # ok: lg.ext.xxe-lxml-etree
    return etree.fromstring(request.body, parser)

def xxe_fixed_literal():
    # ok: lg.ext.xxe-lxml-etree
    return etree.XML("<a>1</a>")

# --- django-ssti-template ---
def django_ssti_unsafe(request):
    # ruleid: lg.ext.django-ssti-template  (sink on following Template call)
    tpl = request.GET["t"]
    # ruleid: lg.ext.django-ssti-template
    return HttpResponse(Template(tpl).render())

def django_ssti_fixed_literal():
    # ok: lg.ext.django-ssti-template
    return HttpResponse(Template("Hello {{ name }}").render(name="x"))

def django_ssti_env(request):
    tpl = os.environ.get("TEMPLATE", "Hello")
    # ok: lg.ext.django-ssti-template
    return HttpResponse(Template(tpl).render())

# --- jinja2-ssti-from-string ---
def jinja_ssti_unsafe(request):
    # ruleid: lg.ext.jinja2-ssti-from-string
    return Environment().from_string(request.GET["t"]).render()

def jinja_ssti_fixed(request):
    # ok: lg.ext.jinja2-ssti-from-string
    return Environment().from_string("Hello {{ name }}").render(name=request.args.get("n"))
