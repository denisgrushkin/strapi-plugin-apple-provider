export default [
  {
    method: 'POST',
    path: '/callback',
    // name of the controller file & the method.
    handler: 'controller.callback',
    config: {
      policies: [],
    },
  },
];
