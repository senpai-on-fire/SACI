import argparse

import saci

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--run-component", type=str, help="Specify the component to run")
    parser.add_argument("-y", "--hypothesis", type=str, help="Add CPV hypothesis")
    parser.add_argument("-v", "--version", action="version", version=f"{saci.__version__}")
    args = parser.parse_args()

    if args.run_component == "orchestrator":
        from .orchestrator import main as orchestrator_main
        if args.hypothesis:
            orchestrator_main(args.hypothesis)
    elif args.run_component == "web":
        try:
            import flask # pyright: ignore [reportMissingImports]
        except ImportError:
            raise RuntimeError("Please install flask before running the web component")
        from .webui.web import app
        app.run()
    else:
        raise RuntimeError("Unknown component to run")


if __name__ == "__main__":
    main()
