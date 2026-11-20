"""Provision LocalGuard on E: only; never train or load model weights.

Run with E:/Program Files/Python/python.exe -I -B <this-file> all.
Commands: install, download, verify, manifest, all. Existing dependency locks
and model revision pins are reused. Only dependencies, not workspace sources,
are sent to package services. The workspace is read-only to this script.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib
import traceback

ROOT = Path(os.environ.get("LOCALGUARD_TRAIN_ROOT", "C:/LocalGuard/training"))
BASE_PYTHON = Path("E:/Program Files/Python/python.exe")
PYTHON = ROOT / "train-env/Scripts/python.exe"
ARTIFACTS = ROOT / "artifacts"
MODEL = ROOT / "base-model"
WORKSPACE = Path(__file__).resolve().parents[1]
REPO = "Qwen/Qwen3.5-4B"
TORCH_URL = (
    "https://download-r2.pytorch.org/whl/cu128/"
    "torch-2.11.0%2Bcu128-cp313-cp313-win_amd64.whl"
    "#sha256=6f367e62fd81b75cdf23ca4b75ced834d2db2cf98d1588ac935bde345de9de23"
)


def write_json(name, data):
    (ARTIFACTS / name).write_text(
        json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )


def read_json(name):
    path = ARTIFACTS / name
    return json.loads(path.read_text("utf-8")) if path.exists() else None


def configure():
    if not ROOT.parent.is_dir():
        raise RuntimeError(f"Expected pre-existing parent directory of {ROOT}")
    directories = ["tmp", "artifacts", "base-model", "cache/pip", "cache/huggingface",
                   "cache/torch", "cache/cuda", "cache/xdg", "cache/inductor", "cache/triton"]
    for directory in directories:
        (ROOT / directory).mkdir(parents=True, exist_ok=True)
    for key in ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HF_HUB_OFFLINE",
                "TRANSFORMERS_OFFLINE", "HF_DATASETS_OFFLINE", "BNB_CUDA_VERSION"):
        os.environ.pop(key, None)
    os.environ.update({
        "TMP": str(ROOT / "tmp"), "TEMP": str(ROOT / "tmp"),
        "TMPDIR": str(ROOT / "tmp"), "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1", "PIP_CONFIG_FILE": os.devnull,
        "PIP_CACHE_DIR": str(ROOT / "cache/pip"), "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "HF_HOME": str(ROOT / "cache/huggingface"),
        "HF_HUB_CACHE": str(ROOT / "cache/huggingface/hub"),
        "HF_XET_CACHE": str(ROOT / "cache/huggingface/xet"),
        "HF_DATASETS_CACHE": str(ROOT / "cache/huggingface/datasets"),
        "HF_TOKEN_PATH": str(ROOT / "cache/huggingface/unused-token"),
        "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1", "HF_HUB_DISABLE_TELEMETRY": "1",
        "HF_HUB_DISABLE_XET": "1", "HF_HUB_ETAG_TIMEOUT": "20",
        "HF_HUB_DOWNLOAD_TIMEOUT": "120", "HF_ENDPOINT": "https://huggingface.co",
        "TORCH_HOME": str(ROOT / "cache/torch"),
        "CUDA_CACHE_PATH": str(ROOT / "cache/cuda"),
        "TORCHINDUCTOR_CACHE_DIR": str(ROOT / "cache/inductor"),
        "TRITON_CACHE_DIR": str(ROOT / "cache/triton"),
        "XDG_CACHE_HOME": str(ROOT / "cache/xdg"),
        "WANDB_DISABLED": "true", "DO_NOT_TRACK": "1",
    })
    sys.dont_write_bytecode = True


def pip_command(*args):
    return [str(PYTHON), "-I", "-B", "-m", "pip", "--isolated", *args]


def install():
    lock = ARTIFACTS / "environment.lock.txt"
    requirements = ["-r", str(lock)] if lock.exists() else [
        "torch @ " + TORCH_URL,
        *tomllib.loads((WORKSPACE / "pyproject.toml").read_text("utf-8"))["project"]["dependencies"],
        *tomllib.loads((WORKSPACE / "pyproject.toml").read_text("utf-8"))["project"]["optional-dependencies"]["train"],
    ]
    command = pip_command(
        "install", "--disable-pip-version-check", "--index-url", "https://pypi.org/simple",
        "--cache-dir", str(ROOT / "cache/pip"), "--only-binary=:all:",
        "--report", str(ARTIFACTS / "bootstrap-pip-report.json"), *requirements,
    )
    with (ARTIFACTS / "bootstrap-install.log").open("a", encoding="utf-8") as log:
        subprocess.run(command, env=os.environ.copy(), stdout=log, stderr=subprocess.STDOUT, check=True)
    subprocess.run(pip_command("check"), check=True)
    freeze = subprocess.check_output(pip_command("freeze", "--all"), text=True)
    lock.write_text(freeze, encoding="utf-8")


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download():
    from huggingface_hub import HfApi, snapshot_download

    pin = read_json("model-revision.json")
    revision = pin["revision"] if pin else "main"
    info = HfApi(endpoint="https://huggingface.co", token=False).model_info(
        REPO, revision=revision, files_metadata=True, timeout=25
    )
    if not re.fullmatch(r"[0-9a-f]{40}", info.sha or ""):
        raise RuntimeError("Hub did not provide an exact 40-character revision")
    if pin and pin["revision"] != info.sha:
        raise RuntimeError("Upstream revision does not match the existing pin")
    filenames = []
    upstream = []
    # Only tensor data, tokenizer/config data and the license; never remote Python.
    allowed = {".json", ".safetensors", ".jinja", ".txt", ".model", ".tiktoken"}
    for item in info.siblings:
        name = item.rfilename
        if ("/" in name or "\\" in name or ":" in name or Path(name).name != name
                or (Path(name).suffix not in allowed and name != "LICENSE")):
            continue
        filenames.append(name)
        lfs = item.lfs
        upstream.append({"name": name, "size": item.size,
                         "sha256": getattr(lfs, "sha256", None), "git_blob": item.blob_id})
    if "config.json" not in filenames or not any(n.endswith(".safetensors") for n in filenames):
        raise RuntimeError("Official snapshot lacks expected config/safetensors")
    pin = {"repo": REPO, "revision": info.sha, "endpoint": "https://huggingface.co",
           "metadata_url": f"https://huggingface.co/api/models/{REPO}/revision/{info.sha}?blobs=true",
           "files": upstream, "expected_bytes": sum(f["size"] or 0 for f in upstream),
           "metadata_fetched_utc": datetime.now(timezone.utc).isoformat()}
    write_json("model-revision.json", pin)
    snapshot_download(
        repo_id=REPO, revision=info.sha, local_dir=str(MODEL),
        cache_dir=str(ROOT / "cache/huggingface/hub"), allow_patterns=filenames,
        token=False, max_workers=2, endpoint="https://huggingface.co",
    )
    verified = []
    for item in upstream:
        path = MODEL / item["name"]
        size = path.stat().st_size
        if item["size"] is not None and size != item["size"]:
            raise RuntimeError(f"Size mismatch: {item['name']}")
        sha256 = file_sha256(path)
        if item["sha256"] and sha256 != item["sha256"]:
            raise RuntimeError(f"Upstream LFS checksum mismatch: {item['name']}")
        if not item["sha256"] and item["git_blob"]:
            git_hash = hashlib.sha1(b"blob " + str(size).encode() + b"\0" + path.read_bytes()).hexdigest()
            if git_hash != item["git_blob"]:
                raise RuntimeError(f"Upstream Git checksum mismatch: {item['name']}")
        verified.append({"name": item["name"], "bytes": size, "sha256": sha256})
    index = MODEL / "model.safetensors.index.json"
    if index.exists():
        referenced = set(json.loads(index.read_text("utf-8"))["weight_map"].values())
        if not referenced.issubset(set(filenames)):
            raise RuntimeError("Some indexed tensor shards are missing")
    write_json("model-download.json", {"complete": True, "revision": info.sha,
                                       "files": verified, "bytes": sum(f["bytes"] for f in verified)})


def verify():
    import importlib
    import site

    result = {"interpreter": sys.executable, "python": sys.version,
              "prefix": sys.prefix, "base_prefix": sys.base_prefix,
              "user_site_enabled": site.ENABLE_USER_SITE, "sys_path": sys.path,
              "training_run": False, "model_weights_loaded": False, "checks": {}}

    def check(name, action):
        try:
            result["checks"][name] = {"passed": True, "details": action()}
        except Exception as exc:
            result["checks"][name] = {"passed": False, "error": f"{type(exc).__name__}: {exc}"}
        write_json("verification.json", result)

    def torch_check():
        import torch
        if not torch.cuda.is_available():
            raise RuntimeError(f"CUDA unavailable; torch={torch.__version__}; built CUDA={torch.version.cuda}")
        prop = torch.cuda.get_device_properties(0)
        with torch.inference_mode():
            x = torch.ones((64, 64), device="cuda", dtype=torch.bfloat16)
            y = x @ x
            torch.cuda.synchronize()
            assert torch.all(y == 64).item(), "CUDA matmul produced incorrect values"
        return {"version": torch.__version__, "built_cuda": torch.version.cuda,
                "device": prop.name, "capability": list(torch.cuda.get_device_capability(0)),
                "compiled_arches": torch.cuda.get_arch_list(), "vram_bytes": prop.total_memory,
                "bf16_supported": torch.cuda.is_bf16_supported(),
                "free_total_bytes": list(torch.cuda.mem_get_info()),
                "bf16_cuda_matmul": "passed (64x64, no gradients)",
                "driver_query": subprocess.check_output([
                    "nvidia-smi", "--query-gpu=name,driver_version,memory.total,compute_cap",
                    "--format=csv,noheader"], text=True).strip()}

    def bnb_check():
        import torch
        import bitsandbytes as bnb
        from bitsandbytes import functional as functional
        from bitsandbytes.cextension import lib
        with torch.inference_mode():
            x = torch.linspace(-1, 1, 4096, device="cuda", dtype=torch.bfloat16)
            quantized, state = functional.quantize_4bit(x, quant_type="nf4", compress_statistics=True)
            restored = functional.dequantize_4bit(quantized, state)
            assert restored.shape == x.shape and torch.isfinite(restored).all().item()
            error = (restored - x).abs().mean().item()
            assert error < 0.1, f"NF4 roundtrip error too large: {error}"
            layer = bnb.nn.Linear4bit(64, 64, bias=False, compute_dtype=torch.bfloat16,
                                     quant_type="nf4", compress_statistics=True).to("cuda")
            output = layer(torch.ones((2, 64), device="cuda", dtype=torch.bfloat16))
            torch.cuda.synchronize()
            assert torch.isfinite(output).all().item()
        return {"version": bnb.__version__, "native_library_type": type(lib).__name__,
                "compiled_with_cuda": lib.compiled_with_cuda, "native_library_path": str(lib._lib._name),
                "nf4_double_quant_roundtrip": "passed", "mean_absolute_error": error,
                "tiny_linear4bit_cuda_forward": "passed (64x64; no backward/optimizer)"}

    def imports_check():
        versions = {}
        for module in ("transformers", "peft", "datasets", "accelerate", "jsonschema",
                       "tree_sitter", "tree_sitter_language_pack", "mcp", "fastapi", "httpx"):
            importlib.import_module(module)
            versions[module] = importlib.metadata.version(module.replace("_", "-"))
        from transformers import Trainer, TrainingArguments, AutoModelForImageTextToText
        from transformers.models.qwen3_5 import Qwen3_5ForConditionalGeneration
        versions["qwen3_5_builtin_model_class"] = Qwen3_5ForConditionalGeneration.__name__
        return versions

    def cli_check():
        run = subprocess.run([str(PYTHON), "-I", "-B", str(WORKSPACE / "scripts/train_adapter.py"),
                              "--help"], capture_output=True, text=True, check=True, env=os.environ.copy())
        return {"exit_code": run.returncode, "stdout": run.stdout}

    def config_check():
        from transformers import AutoConfig, AutoTokenizer, AutoModelForImageTextToText
        config = AutoConfig.from_pretrained(str(MODEL), local_files_only=True, trust_remote_code=False)
        tokenizer = AutoTokenizer.from_pretrained(str(MODEL), local_files_only=True, trust_remote_code=False)
        assert tokenizer.chat_template, "Tokenizer chat template is missing"
        return {"model_type": config.model_type, "config_class": type(config).__name__,
                "tokenizer_class": type(tokenizer).__name__,
                "built_in_auto_model_mapping": config.__class__ in AutoModelForImageTextToText._model_mapping,
                "chat_template_present": bool(tokenizer.chat_template), "remote_code_trusted": False}

    check("torch_cuda", torch_check)
    check("bitsandbytes_cuda_nf4", bnb_check)
    check("training_dependency_imports", imports_check)
    check("localguard_cli_help", cli_check)
    if (MODEL / "config.json").exists():
        check("local_config_tokenizer", config_check)
    else:
        result["checks"]["local_config_tokenizer"] = {"passed": False, "error": "Model not downloaded"}
    result["limits"] = ["No training, optimizer steps, backward pass, or model-weight loading performed.",
                         "Tiny CUDA/NF4 checks do not establish full-model QLoRA fit in 8 GiB at seq4096.",
                         "Real provenance dataset curation and held-out evaluation remain required."]
    write_json("verification.json", result)
    print(json.dumps(result, indent=2))
    if any(not item["passed"] for item in result["checks"].values()):
        raise RuntimeError("One or more provisioning checks failed; see verification.json")


def size_of(path):
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file()) if path.exists() else 0


def manifest():
    packages = dict(sorted((d.metadata["Name"], d.version) for d in importlib.metadata.distributions()))
    pip_check = subprocess.run(pip_command("check"), capture_output=True, text=True)
    freeze = subprocess.check_output(pip_command("freeze", "--all"), text=True)
    if "torch" in {k.lower() for k in packages}:
        (ARTIFACTS / "environment.lock.txt").write_text(freeze, encoding="utf-8")
    dependencies = tomllib.loads((WORKSPACE / "pyproject.toml").read_text("utf-8"))["project"]
    verification = read_json("verification.json") or {}
    model_download = read_json("model-download.json") or {}
    checks = verification.get("checks", {})
    complete = (pip_check.returncode == 0 and model_download.get("complete", False)
                and bool(checks) and all(item["passed"] for item in checks.values()))
    manifest_data = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "provisioning_complete": complete,
        "training_authorized": False,
        "failed_checks": [name for name, item in checks.items() if not item["passed"]],
        "cache_environment": {key: os.environ[key] for key in (
            "TMP", "TEMP", "PIP_CACHE_DIR", "HF_HOME", "HF_HUB_CACHE", "HF_XET_CACHE",
            "HF_DATASETS_CACHE", "TORCH_HOME", "CUDA_CACHE_PATH", "TORCHINDUCTOR_CACHE_DIR")},
        "install_reports": [str(p) for p in ARTIFACTS.glob("*pip*report.json")],
        "purpose": "LocalGuard provisioning only; NOT authorization to train",
        "interpreter": str(PYTHON), "base_python": str(BASE_PYTHON), "python_version": sys.version,
        "model_path": str(MODEL), "repo": REPO, "model_revision": read_json("model-revision.json"),
        "model_download": read_json("model-download.json"), "download_attempt": read_json("download-status.json"),
        "packages": packages, "pip_check": {"returncode": pip_check.returncode,
                                               "output": pip_check.stdout + pip_check.stderr},
        "required_app_dependencies": dependencies["dependencies"],
        "required_training_dependencies": dependencies["optional-dependencies"]["train"],
        "project_pyproject_sha256": file_sha256(WORKSPACE / "pyproject.toml"),
        "train_script_sha256": file_sha256(WORKSPACE / "scripts/train_adapter.py"),
        "bootstrap_script": str(Path(__file__).resolve()), "torch_official_wheel": TORCH_URL,
        "package_index": "https://pypi.org/simple", "model_endpoint": "https://huggingface.co",
        "verification": read_json("verification.json"),
        "sizes_bytes": {"environment": size_of(ROOT / "train-env"), "model": size_of(MODEL),
                        "cache": size_of(ROOT / "cache"), "tmp": size_of(ROOT / "tmp"),
                        "root_total": size_of(ROOT), "E_free": shutil.disk_usage(ROOT).free},
        "scope": "Only the configured training root and the workspace bootstrap script written; no app configuration changes",
    }
    write_json("training-manifest.json", manifest_data)
    print(json.dumps({"manifest": str(ARTIFACTS / "training-manifest.json"),
                      "packages": packages, "sizes_bytes": manifest_data["sizes_bytes"]}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("install", "download", "verify", "manifest", "all"))
    args = parser.parse_args()
    configure()
    if not PYTHON.exists():
        subprocess.run([str(BASE_PYTHON), "-I", "-B", "-m", "venv", str(ROOT / "train-env")], check=True)
    if Path(sys.prefix).resolve() != (ROOT / "train-env").resolve():
        return subprocess.call([str(PYTHON), "-I", "-B", str(Path(__file__).resolve()), args.command], env=os.environ.copy())
    cfg = (ROOT / "train-env/pyvenv.cfg").read_text("utf-8")
    if "include-system-site-packages = false" not in cfg:
        raise RuntimeError("Refusing non-isolated training environment")
    commands = ["install", "download", "verify"] if args.command == "all" else [args.command]
    failed = False
    for command in commands:
        try:
            globals()[command]()
            if command == "download":
                write_json("download-status.json", {"completed": True})
        except Exception as exc:
            failed = True
            error = {"completed": False, "stage": command, "error": f"{type(exc).__name__}: {exc}",
                     "at_utc": datetime.now(timezone.utc).isoformat()}
            write_json(f"{command}-status.json", error)
            traceback.print_exc()
            if command == "install":
                break
    if args.command != "manifest":
        manifest()
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
