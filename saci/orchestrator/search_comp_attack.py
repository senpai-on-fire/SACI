from cpv_definitions import CPVS
import re
from difflib import SequenceMatcher


def normalize_text(text):
    if not text:
        return ""
    normalized = re.sub(r'[^\w\s]', ' ', text.lower())
    normalized = re.sub(r'\s+', ' ', normalized).strip()
    return normalized


def calculate_similarity(text1, text2):
    return SequenceMatcher(None, normalize_text(text1), normalize_text(text2)).ratio()


def fuzzy_match(query, target, threshold=0.6):
    if not query or not target:
        return False
    
    if normalize_text(query) == normalize_text(target):
        return True
    
    # Substring match
    if normalize_text(query) in normalize_text(target):
        return True
    
    # Fuzzy similarity match
    if calculate_similarity(query, target) >= threshold:
        return True
    
    # Word-by-word matching for compound terms
    query_words = set(normalize_text(query).split())
    target_words = set(normalize_text(target).split())
    
    # If most query words are found in target
    if query_words and len(query_words.intersection(target_words)) / len(query_words) >= 0.7:
        return True
    
    return False


def search_component_fuzzy(query, component_name):
    if not query:
        return True
    
    component_aliases = {
        'compass': ['compasssensor', 'magnetometer'],
        'gps': ['gpsreceiver', 'gnssreceiver'],
        'gnss': ['gnssreceiver', 'gpsreceiver'], 
        'magnetometer': ['compasssensor', 'compass'],
        'wifi': ['wireless', 'wlan'],
        'serial': ['uart', 'communication'],
        'camera': ['optical', 'vision'],
        'pwm': ['pwmchannel', 'pulse width modulation'],
        'smbus': ['i2c', 'bus']
    }
    
    query_norm = normalize_text(query)
    component_norm = normalize_text(component_name)
    
    # Direct fuzzy match
    if fuzzy_match(query, component_name, threshold=0.6):
        return True
    
    # Check aliases
    for alias, synonyms in component_aliases.items():
        if query_norm == alias or any(query_norm == syn for syn in synonyms):
            if component_norm == alias or any(component_norm == syn for syn in synonyms):
                return True
    
    return False


def search_cpvs(entry_component=None, attack_vector=None):
    matching_cpvs = []

    for cpv in CPVS:
        # Check entry component match with fuzzy matching
        if entry_component:
            component_match = search_component_fuzzy(entry_component, cpv.entry_component.__class__.__name__)
            if not component_match:
                continue

        # Check attack vector match with fuzzy matching
        if attack_vector:
            vector_match = any(fuzzy_match(attack_vector, vec.name, threshold=0.5) for vec in cpv.attack_vectors)
            if not vector_match:
                continue

        print(cpv)
        matching_cpvs.append(cpv)

    return format_results(matching_cpvs)


def get_suggestions(query, candidates, max_suggestions=5):
    if not query or not candidates:
        return []
    
    suggestions = []
    for candidate in candidates:
        similarity = calculate_similarity(query, candidate)
        if similarity > 0.3:  # Lower threshold for suggestions
            suggestions.append((candidate, similarity))
    
    # Sort by similarity score and return top suggestions
    suggestions.sort(key=lambda x: x[1], reverse=True)
    return [s[0] for s in suggestions[:max_suggestions]]


def get_available_options():
    entry_components = set()
    attack_vectors = set()
    
    for cpv in CPVS:
        entry_components.add(cpv.entry_component.__class__.__name__)
        for vec in cpv.attack_vectors:
            attack_vectors.add(vec.name)
    
    return sorted(entry_components), sorted(attack_vectors)


def search_cpvs_with_suggestions(entry_component=None, attack_vector=None):
    matching_cpvs = search_cpvs(entry_component, attack_vector)
    
    if not matching_cpvs:
        available_components, available_vectors = get_available_options()
        
        suggestions = []
        if entry_component:
            comp_suggestions = get_suggestions(entry_component, available_components)
            if comp_suggestions:
                suggestions.append(f"Entry component suggestions: {', '.join(comp_suggestions)}")
        
        if attack_vector:
            vector_suggestions = get_suggestions(attack_vector, available_vectors)
            if vector_suggestions:
                suggestions.append(f"Attack vector suggestions: {', '.join(vector_suggestions)}")
        
        if suggestions:
            print("No exact matches found. Did you mean:")
            for suggestion in suggestions:
                print(f"  {suggestion}")
            print()
    
    return matching_cpvs


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
    print("=== CPV Search Tool (By Component + Attack Vector) ===")
    print("Type 'help' for available options, 'exit' to quit, or press Enter to skip a field.\n")
    
    while True:
        print("Enter the entry component (e.g., Magnetometer, GPS, Compass, etc.):")
        entry_component = input().strip()
        
        if entry_component.lower() == "exit":
            break
        elif entry_component.lower() == "help":
            available_components, available_vectors = get_available_options()
            print(f"\nAvailable Entry Components:\n{', '.join(available_components)}")
            print(f"\nAvailable Attack Vectors:\n{', '.join(available_vectors[:10])}... (and {len(available_vectors)-10} more)")
            print()
            continue

        print("Enter the attack vector (e.g., GPS Spoofing, EMI, Magnetic Interference, etc.):")
        attack_vector = input().strip()
        if attack_vector.lower() == "exit":
            break

        entry_component = entry_component if entry_component else None
        attack_vector = attack_vector if attack_vector else None

        results = search_cpvs_with_suggestions(entry_component, attack_vector)

        if results:
            for result in results:
                print(result)
        else:
            print("No matching CPVs found.")

        print("\nSearch again or type 'exit' at the next prompt to quit.\n")
