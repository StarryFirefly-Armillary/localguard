import json


def tool_text(data):
    return json.dumps(data, ensure_ascii=False, separators=(',', ':'))


def result_bytes(data):
    result = {'isError': False, 'content': [{'type': 'text', 'text': tool_text(data)}], 'structuredContent': data}
    return len(json.dumps(result, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
