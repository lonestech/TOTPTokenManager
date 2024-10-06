const config = {
    API_BASE_URL: process.env.REACT_APP_API_BASE_URL || 'http://localhost:8080',
    GITHUB_AUTH_URL: process.env.REACT_APP_GITHUB_AUTH_URL || 'http://localhost:8080/api/github/auth',
};

export default config;