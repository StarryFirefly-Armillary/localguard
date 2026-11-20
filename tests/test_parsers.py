import pytest

from localguard.config import Config
from localguard.registry import ToolRegistry

SAMPLES = {
    '.py':('python','def greet():\n    return "你好"\n'),
    '.js':('javascript','function greet() {\n return "hello";\n}\n'),
    '.ts':('typescript','function greet(): string {\n return "hello";\n}\n'),
    '.tsx':('tsx','const App = () => <div>hello</div>;\n'),
    '.java':('java','class App {\n String greet() { return "hello"; }\n}\n'),
    '.go':('go','package main\nfunc main() {}\n'),
    '.rs':('rust','fn main() {\n println!("hello");\n}\n'),
    '.c':('c','int main(void) {\n return 0;\n}\n'),
    '.cpp':('cpp','int main() {\n return 0;\n}\n'),
    '.php':('php','<?php\nfunction greet() { return "hello"; }\n'),
    '.rb':('ruby','def greet\n "hello"\nend\n'),
    '.sol':('solidity','pragma solidity ^0.8.0;\ncontract App { function greet() public pure returns(uint) { return 1; } }\n')
}


@pytest.mark.anyio
@pytest.mark.parametrize('suffix',SAMPLES)
async def test_installed_offline_grammar_real_nodes_and_shared_tokens(tmp_path,suffix):
    language,code = SAMPLES[suffix]
    file = tmp_path/('sample'+suffix)
    file.write_text(code,encoding='utf-8')
    registry = ToolRegistry(Config(allowed_roots=[tmp_path],data_dir=tmp_path/'state'))
    ast = await registry.call('get_ast',{'path':str(file)},'s')
    assert not ast['isError'],ast
    assert ast['data']['language']==language
    assert not ast['data']['parse_error']
    assert ast['data']['nodes'][0]['start_line']==1
    preview = await registry.call('view_file',{'path':str(file)},'s')
    assert not preview['isError'],preview
    assert preview['data']['language']==language
    assert any(line['tokens'] for line in preview['data']['lines'])
    for row in preview['data']['lines']:
        for token in row['tokens']:
            assert 0<=token['start']<token['end']<=len(row['text'])
    assert registry.parser.parse.cache_info().hits>0
