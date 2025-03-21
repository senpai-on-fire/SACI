from cpv_definitions import CPVS


def search_cpvs(vuln_component=None):
    matching_cpvs = []

    for cpv in CPVS:
        if vuln_component:
            comp_match = any(vuln_component in comp.__class__.__name__ for comp in [cpv.entry_component])
            if not comp_match:
                continue

        matching_cpvs.append(cpv)

    return format_results(matching_cpvs)


def format_results(cpvs):
    formatted_results = []
    for cpv in cpvs:
        print(cpv)
        initial_conditions_formatted = "\n        - " + "\n        - ".join(
            [f"{key}: {value}" for key, value in cpv.initial_conditions.items()]
        )

        cpv_info = (
            f"""
        Match Found: {cpv.NAME}
        --------------------------------------------
        CPV Path: {", ".join([comp.__class__.__name__ for comp in cpv.required_components])}
        Entry Component: {cpv.entry_component.__class__.__name__}
        Exit Component: {cpv.exit_component.__class__.__name__}
        Vulnerabilities: {", ".join([vuln.__class__.__name__ for vuln in cpv.vulnerabilities])}
        Initial Conditions:{initial_conditions_formatted}
        Attack Requirements:
        - """
            + "\n        - ".join(cpv.attack_requirements)
            + """
        Attack Vectors:
        - """
            + "\n        - ".join([vec.name for vec in cpv.attack_vectors])
            + """
        Attack Impacts:
        - """
            + "\n        - ".join([impact.description for impact in cpv.attack_impacts])
            + """
        Exploit Steps:
        - """
            + "\n        - ".join(cpv.exploit_steps)
            + f"""
        Associated Files: {", ".join(cpv.associated_files) if cpv.associated_files else "None"}
        References: {", ".join(cpv.reference_urls)}
        """
        )
        formatted_results.append(cpv_info)
    return formatted_results


if __name__ == "__main__":
    while True:
        print("Enter the CPS component (e.g., Magnetometer, GPSReceiver, etc.):")
        vuln_component = input().strip()
        if vuln_component.lower() == "exit":
            break

        results = search_cpvs(vuln_component)

        if results:
            for result in results:
                print(result)
        else:
            print("No matching CPVs found.")

        print("\nSearch again or type 'exit' at the next prompt to quit.\n")
