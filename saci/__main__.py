import argparse

import saci


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--run-component", type=str, help="Specify the component to run")
    parser.add_argument("-v", "--version", action="version", version=f"{saci.__version__}")
    parser.add_argument("-a", "--address", default="127.0.0.1", help="Address to listen on")
    parser.add_argument("-p", "--port", default=8000, help="Port to listen on")
    args = parser.parse_args()

    if args.run_component == "orchestrator":
        from .orchestrator import main as orchestrator_main

        orchestrator_main()
    elif args.run_component == "web":
        import uvicorn

        from .webui.web import app

        uvicorn.run(app, host=args.address, port=args.port)
    else:
        raise RuntimeError("Unknown component to run")


if __name__ == "__main__":
    main()
