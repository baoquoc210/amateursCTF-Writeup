from importlib.machinery import SourcelessFileLoader
from importlib.util import spec_from_loader, module_from_spec


def load_module_from_pyc(path: str, name: str):
    loader = SourcelessFileLoader(name, path)
    spec = spec_from_loader(name, loader)
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module


def main():
    # Read n and c captured from the remote instance
    with open("current_nc.txt", "r", encoding="utf-8") as f:
        n_str = f.readline().strip()
        c_str = f.readline().strip()

    # Load the precompiled small-root solver
    sol = load_module_from_pyc(
        "__pycache__/solve_addition2_bd.cpython-312.pyc",
        "solve_addition2_bd",
    )

    # This may take a long time; that is fine because this script is
    # intended to be launched in the background.
    flag_bytes = sol.solve_from_nc_line(n_str, c_str)

    # Persist the result for later inspection
    with open("flag_output.txt", "wb") as out:
        out.write(flag_bytes)

    # Also print to stdout for the log
    try:
        print("FLAG_READY:", flag_bytes.decode(), flush=True)
    except Exception:
        print("FLAG_READY_HEX:", flag_bytes.hex(), flush=True)


if __name__ == "__main__":
    main()

