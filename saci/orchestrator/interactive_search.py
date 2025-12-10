"""
Interactive CLI for CPV search with ML features.
"""

from ml_search import AdvancedCPVSearch, print_search_results
import sys


def interactive_search():
    """Interactive search session."""
    print("="*80)
    print("SACI CPV Advanced Search")
    print("="*80)
    print("\nInitializing search engine...")
    
    searcher = AdvancedCPVSearch()
    
    print("\nReady! Type your queries in natural language.")
    print("Commands:")
    print("  • Type any question or keywords to search")
    print("  • 'filter' - Search with component/vector/impact filters")
    print("  • 'quit' or 'exit' - Exit the program")
    print("\n" + "="*80 + "\n")
    
    while True:
        try:
            # Get user input
            query = input("Search: ").strip()
            
            if not query:
                continue
            
            if query.lower() in ['quit', 'exit', 'q']:
                print("\n Goodbye!")
                break
            
            if query.lower() == 'filter':
                # Filtered search
                print("\n Filtered Search")
                print("-" * 40)
                
                query = input("Query: ").strip()
                if not query:
                    continue
                
                component = input("Component (optional): ").strip() or None
                attack_vector = input("Attack Vector (optional): ").strip() or None
                attack_impact = input("Attack Impact (optional): ").strip() or None
                
                try:
                    top_k = int(input("Max results [10]: ").strip() or "10")
                except ValueError:
                    top_k = 10
                
                results = searcher.search_with_filters(
                    query=query,
                    component=component,
                    attack_vector=attack_vector,
                    attack_impact=attack_impact,
                    top_k=top_k
                )
            else:
                # Regular search
                results = searcher.search(query, top_k=10)
            
            # Display results
            print_search_results(results, show_suggestions=True)
            
        except KeyboardInterrupt:
            print("\n\n Goodbye!")
            break
        except Exception as e:
            print(f"\n Error: {e}")
            import traceback
            traceback.print_exc()
            print("Please try again.\n")


if __name__ == "__main__":
    interactive_search()
