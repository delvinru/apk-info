"""Checks that apk_info/__init__.pyi describes the compiled module.

The stub is written by hand, so it drifts: a field that no longer exists, a
missing signature variant, a set annotated as a list. These tests compare it
with the module two ways:

- statically: classes, methods, their parameters and attributes;
- at runtime: every APK method is called on the repository's fixtures and its
  result is checked against the annotated return type.

Run after building the module: `maturin develop -m python/Cargo.toml`, then
`pytest python/tests`.
"""

import ast
import inspect
import types
import typing
from pathlib import Path

import pytest

import apk_info
from apk_info import APK

ROOT = Path(__file__).resolve().parents[2]
STUB = ROOT / "python" / "apk_info" / "__init__.pyi"
FIXTURES = sorted(
    path
    for directory in ("crates/zip/tests/fixtures", "core/tests/fixtures")
    for path in (ROOT / directory).iterdir()
    if path.suffix in (".apk", ".apks")
)

TREE = ast.parse(STUB.read_text())


def stub_classes(nodes, prefix=""):
    """Maps `Class` and `Class.Nested` to their stub methods and attributes."""
    classes = {}
    for node in nodes:
        if not isinstance(node, ast.ClassDef):
            continue
        name = prefix + node.name
        methods = {
            item.name: [arg.arg for arg in item.args.args if arg.arg not in ("self", "cls")]
            for item in node.body
            if isinstance(item, ast.FunctionDef)
        }
        attributes = {
            item.target.id
            for item in node.body
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)
        }
        classes[name] = (methods, attributes)
        classes.update(stub_classes(node.body, name + "."))
    return classes


def runtime_classes():
    """Maps the module's classes, nested ones included, to their methods and attributes."""
    classes = {}

    def visit(cls, prefix=""):
        name = prefix + cls.__name__
        methods, attributes = {}, set()
        for key, value in vars(cls).items():
            if isinstance(value, type):
                visit(value, name + ".")
            elif key.startswith("_"):
                continue
            elif inspect.isgetsetdescriptor(value) or isinstance(value, property):
                attributes.add(key)
            elif callable(value):
                methods[key] = getattr(value, "__text_signature__", None)
        classes[name] = (methods, attributes)

    for value in vars(apk_info).values():
        if isinstance(value, type) and value.__module__.startswith("apk_info"):
            visit(value)
    return classes


def text_signature_params(signature):
    """Parameter names of a pyo3 `__text_signature__` like `($self, tag, name)`."""
    params = []
    for param in signature.strip("()").split(","):
        param = param.split("=")[0].strip()
        if param and param not in ("$self", "$cls", "/", "*"):
            params.append(param)
    return params


STUBS = stub_classes(TREE.body)
RUNTIME = runtime_classes()


@pytest.mark.parametrize("name", sorted(set(STUBS) | set(RUNTIME)))
def test_class_matches_stub(name):
    assert name in STUBS, f"{name} is missing from the stub"
    assert name in RUNTIME, f"{name} is in the stub but not in the module"

    stub_methods, stub_attributes = STUBS[name]
    methods, attributes = RUNTIME[name]

    assert stub_attributes == attributes, f"{name}: attributes differ"

    stub_methods = {k: v for k, v in stub_methods.items() if not k.startswith("_")}
    assert set(stub_methods) == set(methods), f"{name}: methods differ"

    for method, params in stub_methods.items():
        signature = methods[method]
        if signature:
            assert params == text_signature_params(signature), f"{name}.{method}: parameters differ"


def stub_namespace():
    """Names the stub's annotations refer to, its type aliases included."""
    namespace = {key: getattr(apk_info, key) for key in dir(apk_info)}
    namespace.update({"Literal": typing.Literal, "PurePath": Path})
    for node in TREE.body:
        if isinstance(node, ast.TypeAlias):
            namespace[node.name.id] = eval(ast.unparse(node.value), namespace)
    return namespace


def matches(value, annotation):
    """A small isinstance for the annotations the stub uses."""
    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)
    if annotation is None or annotation is type(None):
        return value is None
    if origin in (typing.Union, types.UnionType):
        return any(matches(value, arg) for arg in args)
    if origin is typing.Literal:
        return value in args
    if origin is tuple:
        return isinstance(value, tuple) and all(map(matches, value, args))
    if origin in (list, set):
        return isinstance(value, origin) and all(matches(item, args[0]) for item in value)
    return isinstance(value, annotation)


APK_STUB = next(node for node in TREE.body if isinstance(node, ast.ClassDef) and node.name == "APK")
NAMESPACE = stub_namespace()
ARGUMENTS = {
    "read": (("AndroidManifest.xml",), {"base": True}),
    "get_resource_value": (("@string/app_name",), {}),
    "get_attribute_value": (("application", "label"), {}),
    "get_all_attribute_values": (("uses-permission", "name"), {}),
}


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda path: path.name)
def test_return_types_match_stub(fixture):
    try:
        apk = APK(fixture)
    except apk_info.APKError:
        pytest.skip("the fixture is broken on purpose")

    for method in APK_STUB.body:
        if not isinstance(method, ast.FunctionDef) or method.name.startswith("_"):
            continue
        annotation = eval(ast.unparse(method.returns), NAMESPACE)
        args, kwargs = ARGUMENTS.get(method.name, ((), {}))
        try:
            value = getattr(apk, method.name)(*args, **kwargs)
        except apk_info.APKError:
            continue
        assert matches(value, annotation), (
            f"{method.name}() returned {value!r:.80}, the stub says {ast.unparse(method.returns)}"
        )


def test_signature_type_lists_every_variant():
    variants = {
        value for value in vars(apk_info.Signature).values() if isinstance(value, type)
    }
    assert set(typing.get_args(NAMESPACE["SignatureType"])) == variants
