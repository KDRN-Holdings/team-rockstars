/**
 * Team Rockstars — front-end configuration.
 *
 * API_BASE  The deployed Worker URL. No trailing slash.
 *           The session travels in an Authorization: Bearer header, so this may
 *           be a different site from the app without iOS Safari dropping it.
 *
 * DEMO_MODE Must stay false in production. true + empty API_BASE runs the UI
 *           on-device for previewing and signs every visitor in as the
 *           administrator — never enable it on a site members can reach.
 */
window.TR_CONFIG = {
  API_BASE: 'https://tr-api.morning-wave-675d.workers.dev',
  DEMO_MODE: false
};
