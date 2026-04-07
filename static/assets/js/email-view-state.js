(function attachEmailViewState(root, factory) {
    const api = factory();

    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }

    if (root) {
        root.EmailViewState = api;
    }
})(typeof window !== 'undefined' ? window : globalThis, function buildEmailViewStateApi() {
    function normalizeContextKey(contextKey) {
        return String(contextKey || '');
    }

    function createEmptyEmailViewState() {
        return {
            allEmails: [],
            filteredEmails: [],
            pendingInsertedEmailIds: [],
            currentEmailMessageId: null,
            currentEmailTagKeys: [],
        };
    }

    function createEmailViewSession() {
        let currentContextKey = '';
        let latestRequestId = 0;

        return {
            getContextKey() {
                return currentContextKey;
            },
            setContext(contextKey) {
                currentContextKey = normalizeContextKey(contextKey);
                latestRequestId += 1;
                return createEmptyEmailViewState();
            },
            beginLoad(contextKey) {
                currentContextKey = normalizeContextKey(contextKey);
                latestRequestId += 1;
                return {
                    requestId: latestRequestId,
                    contextKey: currentContextKey,
                };
            },
            shouldApply(requestToken) {
                return Boolean(
                    requestToken &&
                    requestToken.requestId === latestRequestId &&
                    requestToken.contextKey === currentContextKey
                );
            },
        };
    }

    return {
        createEmailViewSession,
        createEmptyEmailViewState,
    };
});
