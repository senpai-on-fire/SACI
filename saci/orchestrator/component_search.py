from cpv_definitions import CPVS
from difflib import SequenceMatcher


# Semantic mappings for components
COMPONENT_SYNONYMS = {
    'compass': ['CompassSensor', 'Magnetometer'],
    'magnetometer': ['CompassSensor', 'Magnetometer'],
    'gps': ['GPSReceiver', 'GNSSReceiver'],
    'gnss': ['GNSSReceiver', 'GPSReceiver'],
    'wifi': ['Wifi', 'WiFiInterface'],
    'motor': ['Motor', 'Steering', 'ESC'],
    'accelerometer': ['Accelerometer'],
    'gyroscope': ['Gyroscope'],
    'barometer': ['Barometer', 'BarometricSensor'],
    'camera': ['Camera', 'DepthCamera'],
    'battery': ['Battery', 'BMS'],
    'lidar': ['Lidar'],
    'optical': ['OpticalFlowSensor'],
    'opticalflow': ['OpticalFlowSensor'],
    'flow': ['OpticalFlowSensor'],
    'airspeed': ['AirspeedSensor'],
    'serial': ['Serial'],
    'controller': ['Controller'],
    'mavlink': ['Mavlink'],
    'pwm': ['PWMChannel'],
    'esc': ['ESC'],
    'smbus': ['SMBus'],
    'debug': ['Debug'],
    'dsmx': ['DSMx'],
    'expresslrs': ['ExpressLRSBackpack'],
    'telnet': ['Telnet'],
    'webserver': ['WebServer'],
    'web': ['WebServer'],
    'icmp': ['ICMP'],
    'ardiscovery': ['ARDiscovery'],
    'gcs': ['GCS'],
}


def semantic_match(query, text, threshold=0.6):
    """Check if query semantically matches text using fuzzy string matching."""
    if not query or not text:
        return False
    
    query_lower = query.lower()
    text_lower = text.lower()
    
    # Exact substring match
    if query_lower in text_lower:
        return True
    
    # Fuzzy match using similarity ratio
    similarity = SequenceMatcher(None, query_lower, text_lower).ratio()
    return similarity >= threshold


def match_component(query, component_class_name):
    """Match component query with actual component class name using synonyms."""
    if not query:
        return True
    
    query_lower = query.lower().strip()
    component_lower = component_class_name.lower()
    
    # Direct match
    if query_lower in component_lower or component_lower in query_lower:
        return True
    
    # Check synonyms
    for key, synonyms in COMPONENT_SYNONYMS.items():
        if query_lower in key or key in query_lower:
            # Check if component matches any synonym
            for synonym in synonyms:
                if synonym.lower() in component_lower or component_lower in synonym.lower():
                    return True
    
    # Fuzzy match as fallback
    return semantic_match(query_lower, component_lower, threshold=0.7)


def search_cpvs(vuln_component=None):
    matching_cpvs = []

    for cpv in CPVS:
        if vuln_component:
            comp_match = match_component(vuln_component, cpv.entry_component.__class__.__name__)
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
