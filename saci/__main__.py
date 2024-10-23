import argparse

import saci

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--run-component", type=str, help="Specify the component to run")
    parser.add_argument("-v", "--version", action="version", version=f"{saci.__version__}")
    args = parser.parse_args()

    if args.run_component == "orchestrator":
        from saci.orchestrator import main as orchestrator_main
        orchestrator_main()
    if args.run_component == "web":
        try:
            import flask
        except ImportError:
            raise RuntimeError("Please install flask before running the web component")
        from saci.webui.web import app
        app.run()
    else:
        raise RuntimeError("Unknown component to run")


if __name__ == "__main__":
    main()
