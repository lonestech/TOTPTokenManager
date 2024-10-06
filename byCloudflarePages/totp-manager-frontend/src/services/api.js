import axios from 'axios';
import config from '../config';

const api = axios.create({
    baseURL: config.API_BASE_URL,
});


export const getTOTPs = () => api.get('/api/totp');
export const addTOTP = (userInfo, secret) => api.post('/api/totp', { userInfo, secret });
export const deleteTOTP = (id) => api.delete(`/api/totp/${id}`);
export const generateToken = (id) => api.get(`/api/totp/${id}/generate`);
export const exportTOTP = (id) => api.get(`/api/totp/${id}/export`);
export const clearAllTOTPs = () => api.post('/api/totp/clear-all');
export const importTOTP = (qrData) => api.post('/api/totp/import', { qrData });
export const getGithubAuthStatus = () => api.get('/api/github/auth-status');
export const uploadToGist = (mode) => api.post('/api/github/upload', { mode });
export const getGistVersions = () => api.get('/api/github/versions');
export const restoreFromGist = (gistId) => api.get(`/api/github/restore?id=${gistId}`);
export const deleteBackup = (gistId) => api.delete(`/api/github/delete-backup?id=${gistId}`);

export default api;