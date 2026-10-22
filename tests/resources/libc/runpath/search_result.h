#ifndef MATRIX_SEARCH_RESULT_H
#define MATRIX_SEARCH_RESULT_H

/* Negative probe outcomes; successful fixture providers return positive values. */
enum SearchResult {
    SEARCH_LOAD_FAILED = -91,
    SEARCH_SYMBOL_MISSING = -92,
    SEARCH_CLOSE_FAILED = -93,
    SEARCH_DIRECTORY_FAILED = -94,
};

#endif
