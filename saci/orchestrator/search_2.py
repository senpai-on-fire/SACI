from cpv_definitions import CPVS


def search_cpvs(entry_component=None, attack_vector=None, attack_impact=None):
    matching_cpvs = []

    for cpv in CPVS:
        # Check entry component match
        if entry_component and cpv.entry_component.__class__.__name__ != entry_component:
            continue

        # Check attack vector match
        if attack_vector:
            vector_match = any(attack_vector.lower() in vec.name.lower() for vec in cpv.attack_vectors)
            if not vector_match:
                continue

        # Check attack impact match
        if attack_impact:
            impact_match = any(attack_impact.lower() in impact.category.lower() for impact in cpv.attack_impacts)
            if not impact_match:
                continue

        print(cpv)
        matching_cpvs.append(cpv)

    return format_results(matching_cpvs)


def format_results(cpvs):
    formatted_results = []
    for cpv in cpvs:
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
        print("Enter the entry component (e.g., Magnetometer, GPSReceiver, etc.):")
        entry_component = input().strip()
        if entry_component.lower() == "exit":
            break

        print("Enter the attack vector (e.g., Electromagnetic Signals Interference, Acoustic Spoofing Signals, etc.):")
        attack_vector = input().strip()

        print("Enter the attack impact (e.g., Loss of Control, Manipulation of Control, Denial of Service, etc.):")
        attack_impact = input().strip()

        results = search_cpvs(entry_component, attack_vector, attack_impact)

        if results:
            for result in results:
                print(result)
        else:
            print("No matching CPVs found.")

        print("\nSearch again or type 'exit' at the next prompt to quit.\n")
