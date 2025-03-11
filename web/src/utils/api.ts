// Custom error class for fetch errors
class FetchError extends Error {
  info: unknown;
  status?: number;
}

// Fetcher function for SWR
export const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
  const res = await fetch(input, init);

  if (res.ok) {
    return await res.json();
  } else {
    const error = new FetchError('error while fetching');
    error.info = await res.json();
    error.status = res.status;
    throw error;
  }
};

// POST data helper function
export const postData = async <T, R = unknown>(url: string, data: T): Promise<R> => {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  });

  if (res.ok) {
    // Handle both JSON responses and empty responses
    const contentType = res.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return await res.json();
    }
    return {} as R; // Empty response
  } else {
    const error = new FetchError('error while posting data');
    try {
      error.info = await res.json();
    } catch {
      error.info = await res.text();
    }
    error.status = res.status;
    throw error;
  }
}; 