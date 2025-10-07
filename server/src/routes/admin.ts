export default [
  {
    method: 'GET',
    path: '/settings',
    handler: 'settings.find',
    config: {
      policies: ['admin::isAuthenticatedAdmin'],
    },
  },
  {
    method: 'POST',
    path: '/settings',
    handler: 'settings.update',
    config: {
      policies: ['admin::isAuthenticatedAdmin'],
    },
  },
];
