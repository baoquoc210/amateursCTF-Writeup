import re
import sys


def build_functions_from_js(js_path: str):
    with open(js_path, "r", encoding="utf-8") as f:
        code = f.read()

    # Drop line comments
    code = re.sub(r"//.*", "", code)

    # Split on semicolons to get top-level statements
    stmts = [s.strip() for s in code.split(";") if s.strip()]

    func_defs = {}
    for stmt in stmts:
        if not stmt.startswith("const "):
            continue
        rest = stmt[len("const ") :].strip()
        if "=" not in rest:
            continue
        name, rhs = rest.split("=", 1)
        name = name.strip()
        rhs = rhs.strip()
        m = re.match(r"\(([^)]*)\)\s*=>\s*(.*)", rhs, flags=re.S)
        if not m:
            continue
        args = m.group(1).strip()
        body = m.group(2).strip()
        func_defs[name] = (args, body)

    py_lines = []

    # Primitive functions: mirror JS semantics used by chal.js
    py_lines.append("def a():\n    return 0")
    py_lines.append("def b(x, y):\n    return x + y")
    py_lines.append("def c(x, y):\n    return x * y")
    py_lines.append("def d(x, y):\n    return x ** y")
    py_lines.append("def e(x, y):\n    return x & y")
    py_lines.append("def f(x, y, z):\n    return y() if x else z()")

    # g(x, y) = x.charCodeAt(y)
    py_lines.append(
        "def g(x, y):\n"
        "    return ord(x[y]) if 0 <= y < len(x) else 0"
    )
    py_lines.append("def h(x):\n    return len(x)")

    # Build A..K etc from captured arrow bodies
    for name, (args, body) in func_defs.items():
        if name in {"a", "b", "c", "d", "e", "f", "g", "h"}:
            continue

        # Normalise whitespace so patterns are predictable
        body = re.sub(r"\s+", " ", body)
        # Convert anonymous arrow functions used as callbacks: () => expr
        body = body.replace("() =>", "lambda :")

        args_py = args
        py_lines.append(f"def {name}({args_py}):\n    return {body}")

    # Execute generated Python code and return its globals
    env: dict = {}
    src = "\n\n".join(py_lines)
    # Optional: uncomment to debug the generated code
    # print(src)
    exec(src, env)
    return env


def main():
    sys.setrecursionlimit(1_000_000)
    env = build_functions_from_js("chal.js")

    A = env["A"]
    B = env["B"]
    K = env["K"]
    a_fn = env["a"]
    b_fn = env["b"]
    c_fn = env["c"]
    d_fn = env["d"]

    # Reconstruct the same constants used in chal.js
    const1 = b_fn(b_fn(d_fn(a_fn(), a_fn()), d_fn(a_fn(), a_fn())), c_fn(d_fn(a_fn(), a_fn()), d_fn(a_fn(), a_fn())))
    const2 = c_fn(
        c_fn(
            b_fn(d_fn(a_fn(), a_fn()), d_fn(a_fn(), a_fn())),
            b_fn(
                c_fn(d_fn(a_fn(), a_fn()), d_fn(a_fn(), a_fn())),
                b_fn(d_fn(a_fn(), a_fn()), d_fn(a_fn(), a_fn())),
            ),
        ),
        c_fn(
            b_fn(d_fn(a_fn(), a_fn()), d_fn(a_fn(), a_fn())),
            c_fn(
                b_fn(d_fn(a_fn(), a_fn()), d_fn(a_fn(), a_fn())),
                b_fn(d_fn(a_fn(), a_fn()), d_fn(a_fn(), a_fn())),
            ),
        ),
    )

    print("const1 (used in B length check):", const1)
    print("const2 (used in A length check):", const2)

    # Examine B(n, const1) for small n to see which argv length passes
    print("\nB(h(argv), const1) for h(argv) = 0..10:")
    for n in range(0, 11):
        print(f" n={n}: {B(n, const1)}")

    # Examine A(len, const2) for plausible flag lengths
    print("\nA(len(flag), const2) for len=0..40:")
    for length in range(0, 41):
        print(f" len={length}: {A(length, const2)}")

    # If a flag candidate is provided on the command line, test it
    if len(sys.argv) > 1:
        flag = sys.argv[1]
        J = env["J"]
        K_fn = env["K"]

        argv_len = 2 + 1  # mimic [\"node\", \"chal.js\", flag]
        ok_len = not B(argv_len, const1)
        k_val = K_fn(flag)
        j_val = J(flag)
        print("\nCandidate flag:", flag)
        print("B(h(argv), const1) == 0? ", ok_len)
        print("K(flag):", k_val)
        print("J(flag):", j_val)


if __name__ == "__main__":
    main()
