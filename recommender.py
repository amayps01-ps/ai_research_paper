from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


def recommend_papers(query, papers, top_n=5):

    if not query or not query.strip():
        return []

    documents = [
        paper["title"] + " " + paper["abstract"]
        for paper in papers
    ]

    all_text = documents + [query]

    vectorizer = TfidfVectorizer(
        stop_words="english",
        ngram_range=(1, 2)
    )

    matrix = vectorizer.fit_transform(all_text)

    query_vector = matrix[-1]
    paper_vectors = matrix[:-1]

    scores = cosine_similarity(
        query_vector,
        paper_vectors
    ).flatten()

    ranked_indices = scores.argsort()[::-1]

    results = []

    for index in ranked_indices:

        score = float(scores[index])

        if score <= 0:
            continue

        paper = papers[index].copy()
        paper["score"] = round(score * 100, 2)

        results.append(paper)

        if len(results) >= top_n:
            break

    return results