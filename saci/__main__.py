import argparse

import saci

def main():
    from saci.orchestrator import main as orchestrator_main

    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--run-component", type=str, help="Specify the saci component to run")
    parser.add_argument("-d", "--device", type=str, help="Specify the device to analyze")
    parser.add_argument("-v", "--version", action="version", version=f"{saci.__version__}")
    args = parser.parse_args()

    if args.run_component == "orchestrator":
        orchestrator_main(args.device)
    else:
        raise RuntimeError("Unknown component to run")


if __name__ == "__main__":
    main()
