"""
Advanced ML-based semantic search for CPVs with:
    - Sentence embeddings for semantic matching
    - Natural language query support
    - Relevance ranking
    - Spell correction
    - Query suggestions
"""

from sentence_transformers import SentenceTransformer, util
import numpy as np
from typing import List, Dict, Tuple, Optional
from difflib import get_close_matches
import re
from collections import defaultdict, Counter
import pickle
import os

# Import from the correct location
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../saci-database'))

from cpv_definitions import CPVS

class AdvancedCPVSearch:
    def __init__(self, model_name: str = 'all-MiniLM-L6-v2', cache_dir: str = './cache'):
        """
        Initialize advanced ML-based CPV search.
        """
        print(f"Loading model: {model_name}...")
        self.model = SentenceTransformer(model_name)
        self.cpvs = CPVS
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
        
        # Storage for embeddings and metadata
        self.cpv_texts = []
        self.cpv_embeddings = None
        self.cpv_metadata = []
        
        # Vocabulary for spell correction and suggestions
        self.vocabulary = set()
        self.term_frequency = Counter()
        self.cpv_terms_map = defaultdict(list)  # term -> [cpv_indices]
        
        # Build or load index
        self._build_or_load_index()
    
    def _extract_cpv_text(self, cpv) -> str:
        """Extract rich text representation from CPV."""
        text_parts = []
        
        # CPV Name
        if hasattr(cpv, 'NAME') and cpv.NAME:
            text_parts.append(cpv.NAME)
        
        # Component information
        if hasattr(cpv, 'entry_component') and cpv.entry_component:
            component_name = cpv.entry_component.__class__.__name__
            text_parts.append(f"Component: {component_name}")
            text_parts.append(component_name)
        
        if hasattr(cpv, 'exit_component') and cpv.exit_component:
            exit_name = cpv.exit_component.__class__.__name__
            text_parts.append(f"Exit: {exit_name}")
        
        # Attack vectors
        if hasattr(cpv, 'attack_vectors') and cpv.attack_vectors:
            for vec in cpv.attack_vectors:
                attack_name = vec.name
                text_parts.append(f"Attack: {attack_name}")
                text_parts.append(attack_name)
        
        # Attack impacts
        if hasattr(cpv, 'attack_impacts') and cpv.attack_impacts:
            for impact in cpv.attack_impacts:
                impact_cat = impact.category
                impact_desc = impact.description
                text_parts.append(f"Impact: {impact_cat}")
                text_parts.append(impact_cat)
                text_parts.append(impact_desc)
        
        # Attack requirements
        if hasattr(cpv, 'attack_requirements') and cpv.attack_requirements:
            for req in cpv.attack_requirements[:3]:  # First 3 requirements
                text_parts.append(req)
        
        return " | ".join(text_parts)
    
    def _extract_metadata(self, cpv) -> Dict:
        """Extract structured metadata from CPV."""
        metadata = {
            'name': getattr(cpv, 'NAME', 'Unknown'),
            'component': None,
            'exit_component': None,
            'attack_vectors': [],
            'attack_impacts': [],
            'keywords': []
        }
        
        if hasattr(cpv, 'entry_component') and cpv.entry_component:
            comp_name = cpv.entry_component.__class__.__name__
            metadata['component'] = comp_name
            metadata['keywords'].append(comp_name.lower())
        
        if hasattr(cpv, 'exit_component') and cpv.exit_component:
            exit_name = cpv.exit_component.__class__.__name__
            metadata['exit_component'] = exit_name
            metadata['keywords'].append(exit_name.lower())
        
        if hasattr(cpv, 'attack_vectors') and cpv.attack_vectors:
            for vec in cpv.attack_vectors:
                metadata['attack_vectors'].append(vec.name)
                metadata['keywords'].append(vec.name.lower())
        
        if hasattr(cpv, 'attack_impacts') and cpv.attack_impacts:
            for impact in cpv.attack_impacts:
                metadata['attack_impacts'].append(impact.category)
                metadata['keywords'].append(impact.category.lower())
        
        return metadata
    
    def _build_vocabulary(self):
        """Build vocabulary for spell correction and suggestions."""
        print("Building vocabulary...")
        
        for idx, cpv in enumerate(self.cpvs):
            text = self.cpv_texts[idx]
            metadata = self.cpv_metadata[idx]
            
            # Extract words from text
            words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
            
            for word in words:
                self.vocabulary.add(word)
                self.term_frequency[word] += 1
                self.cpv_terms_map[word].append(idx)
            
            # Add structured keywords
            for keyword in metadata['keywords']:
                keyword_words = re.findall(r'\b[a-zA-Z]{3,}\b', keyword.lower())
                for word in keyword_words:
                    self.vocabulary.add(word)
                    self.term_frequency[word] += 1
                    self.cpv_terms_map[word].append(idx)
        
        print(f"Vocabulary size: {len(self.vocabulary)} terms")
    
    def _build_or_load_index(self):
        """Build or load cached embeddings index."""
        cache_file = os.path.join(self.cache_dir, 'cpv_embeddings.pkl')
        
        if os.path.exists(cache_file):
            print("Loading cached embeddings...")
            try:
                with open(cache_file, 'rb') as f:
                    cache = pickle.load(f)
                    self.cpv_texts = cache['texts']
                    self.cpv_embeddings = cache['embeddings']
                    self.cpv_metadata = cache['metadata']
                    self.vocabulary = cache['vocabulary']
                    self.term_frequency = cache['term_frequency']
                    self.cpv_terms_map = cache['cpv_terms_map']
                print(f"Loaded {len(self.cpvs)} CPVs from cache")
                return
            except Exception as e:
                print(f"Cache load failed: {e}, rebuilding...")
        
        print("Building embeddings index...")
        
        # Extract texts and metadata
        for cpv in self.cpvs:
            text = self._extract_cpv_text(cpv)
            metadata = self._extract_metadata(cpv)
            
            self.cpv_texts.append(text)
            self.cpv_metadata.append(metadata)
        
        # Generate embeddings
        print("Encoding CPV texts...")
        self.cpv_embeddings = self.model.encode(
            self.cpv_texts,
            convert_to_numpy=True,
            show_progress_bar=True,
            batch_size=32
        )
        
        # Build vocabulary
        self._build_vocabulary()
        
        # Cache everything
        print("Caching embeddings...")
        try:
            with open(cache_file, 'wb') as f:
                pickle.dump({
                    'texts': self.cpv_texts,
                    'embeddings': self.cpv_embeddings,
                    'metadata': self.cpv_metadata,
                    'vocabulary': self.vocabulary,
                    'term_frequency': self.term_frequency,
                    'cpv_terms_map': self.cpv_terms_map
                }, f)
            print(f"Indexed {len(self.cpvs)} CPVs")
        except Exception as e:
            print(f"Cache save failed: {e}")
    
    def spell_correct(self, query: str) -> Tuple[str, List[str]]:
        """
        Auto-correct spelling in query.
        """
        words = re.findall(r'\b[a-zA-Z]{3,}\b', query.lower())
        corrected_words = []
        corrections = []
        
        for word in words:
            if word in self.vocabulary:
                corrected_words.append(word)
            else:
                # Find close matches
                matches = get_close_matches(
                    word, 
                    self.vocabulary, 
                    n=1, 
                    cutoff=0.7
                )
                
                if matches:
                    corrected = matches[0]
                    corrected_words.append(corrected)
                    corrections.append(f"{word} → {corrected}")
                else:
                    corrected_words.append(word)
        
        corrected_query = ' '.join(corrected_words)
        return corrected_query, corrections
    
    def suggest_queries(self, query: str, n: int = 5) -> List[str]:
        """
        Suggest related search terms based on vocabulary and co-occurrence.
        """
        words = re.findall(r'\b[a-zA-Z]{3,}\b', query.lower())
        
        # Find related terms that co-occur with query words
        related_cpvs = set()
        for word in words:
            if word in self.cpv_terms_map:
                related_cpvs.update(self.cpv_terms_map[word])
        
        # Count term frequencies in related CPVs
        related_terms = Counter()
        for cpv_idx in related_cpvs:
            for keyword in self.cpv_metadata[cpv_idx]['keywords']:
                keyword_words = re.findall(r'\b[a-zA-Z]{3,}\b', keyword.lower())
                for word in keyword_words:
                    if word not in words:  # Don't suggest terms already in query
                        related_terms[word] += 1
        
        # Get top related terms
        suggestions = []
        for term, count in related_terms.most_common(n):
            suggestions.append(f"{query} {term}")
        
        # Also add component-specific suggestions
        component_suggestions = []
        for metadata in self.cpv_metadata:
            if metadata['component']:
                comp_lower = metadata['component'].lower()
                if any(word in comp_lower for word in words):
                    if metadata['attack_vectors']:
                        for attack in metadata['attack_vectors'][:1]:  # First attack
                            suggestion = f"{metadata['component']} {attack}"
                            if suggestion.lower() not in [s.lower() for s in component_suggestions]:
                                component_suggestions.append(suggestion)
                                break
        
        # Combine suggestions
        all_suggestions = suggestions + component_suggestions[:n-len(suggestions)]
        return all_suggestions[:n]
    
    def search(
        self,
        query: str,
        top_k: int = 10,
        similarity_threshold: float = 0.2,
        auto_correct: bool = True,
        return_suggestions: bool = True
    ) -> Dict:
        """
        Advanced semantic search with all features.
        Args:
            query: Natural language search query
            top_k: Number of results to return
            similarity_threshold: Minimum similarity score (0-1)
            auto_correct: Enable spell correction
            return_suggestions: Return query suggestions
        Returns:
            Dictionary with results, corrections, and suggestions
        """
        original_query = query
        corrections = []
        
        # Spell correction
        if auto_correct:
            query, corrections = self.spell_correct(query)
        
        # Generate query embedding
        query_embedding = self.model.encode(query, convert_to_numpy=True)
        
        # Calculate cosine similarities
        similarities = util.cos_sim(query_embedding, self.cpv_embeddings)[0].numpy()
        
        # Get top-k results
        top_indices = np.argsort(similarities)[::-1]
        
        # Filter by threshold and collect results
        results = []
        for idx in top_indices:
            score = float(similarities[idx])
            if score >= similarity_threshold:
                cpv = self.cpvs[idx]
                metadata = self.cpv_metadata[idx]
                
                results.append({
                    'cpv': cpv,
                    'score': score,
                    'name': metadata['name'],
                    'component': metadata['component'],
                    'attack_vectors': metadata['attack_vectors'],
                    'attack_impacts': metadata['attack_impacts']
                })
                
                if len(results) >= top_k:
                    break
        
        # Generate suggestions
        suggestions = []
        if return_suggestions and len(results) > 0:
            suggestions = self.suggest_queries(query, n=5)
        
        return {
            'query': {
                'original': original_query,
                'corrected': query if corrections else None,
                'corrections': corrections
            },
            'results': results,
            'suggestions': suggestions,
            'total_found': len(results)
        }
    
    def search_with_filters(
        self,
        query: str,
        component: Optional[str] = None,
        attack_vector: Optional[str] = None,
        attack_impact: Optional[str] = None,
        top_k: int = 10,
        auto_correct: bool = True
    ) -> Dict:
        """
        Search with component/vector/impact filters.
        """
        # First do semantic search with high top_k
        search_results = self.search(
            query,
            top_k=len(self.cpvs),
            similarity_threshold=0.0,
            auto_correct=auto_correct,
            return_suggestions=False
        )
        
        # Apply filters
        filtered_results = []
        for result in search_results['results']:
            # Component filter
            if component and result['component']:
                if component.lower() not in result['component'].lower():
                    continue
            
            # Attack vector filter
            if attack_vector and result['attack_vectors']:
                vector_match = any(
                    attack_vector.lower() in vec.lower()
                    for vec in result['attack_vectors']
                )
                if not vector_match:
                    continue
            
            # Attack impact filter
            if attack_impact and result['attack_impacts']:
                impact_match = any(
                    attack_impact.lower() in imp.lower()
                    for imp in result['attack_impacts']
                )
                if not impact_match:
                    continue
            
            filtered_results.append(result)
            
            if len(filtered_results) >= top_k:
                break
        
        # Generate suggestions based on filters
        suggestions = self.suggest_queries(query, n=5)
        
        search_results['results'] = filtered_results
        search_results['total_found'] = len(filtered_results)
        search_results['suggestions'] = suggestions
        
        return search_results


def print_search_results(search_output: Dict, show_suggestions: bool = True):
    """Pretty print search results."""
    query_info = search_output['query']
    results = search_output['results']
    suggestions = search_output.get('suggestions', [])
    
    print("\n" + "="*80)
    print(" SEARCH RESULTS")
    print("="*80)
    
    # Query information
    print(f"\n Original Query: {query_info['original']}")
    if query_info['corrections']:
        print(f"Auto-corrected to: {query_info['corrected']}")
        for correction in query_info['corrections']:
            print(f"   • {correction}")
    
    # Results
    print(f"\n Found {search_output['total_found']} results:\n")
    
    if not results:
        print("No matching CPVs found. Try:")
        print("  • Using different keywords")
        print("  • Checking spelling")
        print("  • Being more general")
    else:
        for i, result in enumerate(results, 1):
            print(f"{i}. [Score: {result['score']:.3f}] {result['name']}")
            
            if result['component']:
                print(f"   Component: {result['component']}")
            
            if result['attack_vectors']:
                print(f"   Attack: {result['attack_vectors'][0]}")
            
            if result['attack_impacts']:
                print(f"   Impact: {result['attack_impacts'][0]}")
            
            print()
    
    # Suggestions
    if show_suggestions and suggestions:
        print("Related searches:")
        for i, suggestion in enumerate(suggestions, 1):
            print(f"   {i}. {suggestion}")
        print()
    
    print("="*80 + "\n")


if __name__ == "__main__":
    # Initialize search engine
    print("Initializing Advanced CPV Search Engine...")
    searcher = AdvancedCPVSearch()
    
    print("\n" + "DEMO: Natural Language Queries" + "\n")
    
    # Example 1: Natural language query with spell correction
    print("\n" + "─"*80)
    print("Example 1: Natural language query with typo")
    print("─"*80)
    results = searcher.search("attacks on compas using sound", top_k=5)
    print_search_results(results)
    
    # Example 2: Complex natural language query
    print("─"*80)
    print("Example 2: Complex query")
    print("─"*80)
    results = searcher.search(
        "how to manipulate drone navigation with magnets",
        top_k=5
    )
    print_search_results(results)
    
    # Example 3: Component-focused query
    print("─"*80)
    print("Example 3: Component-focused")
    print("─"*80)
    results = searcher.search(
        "GPS spoofing to control flight path",
        top_k=5
    )
    print_search_results(results)
    
    # Example 4: With filters
    print("─"*80)
    print("Example 4: Query with filters")
    print("─"*80)
    results = searcher.search_with_filters(
        query="denial of service",
        component="Wifi",
        top_k=5
    )
    print_search_results(results)
    
    # Example 5: Impact-focused
    print("─"*80)
    print("Example 5: Impact-focused query")
    print("─"*80)
    results = searcher.search(
        "attacks that cause loss of control",
        top_k=5
    )
    print_search_results(results)
