import argparse

import saci

def main():
    from saci.orchestrator import main as orchestrator_main

    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--run-component", type=str, help="Specify the component to run")
    parser.add_argument("-v", "--version", action="version", version=f"{saci.__version__}")
    args = parser.parse_args()

    if args.run_component == "orchestrator":
        orchestrator_main()
    else:
        raise RuntimeError("Unknown component to run")


if __name__ == "__main__":
    main()