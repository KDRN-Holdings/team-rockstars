/**
 * Team Rockstars — front-end configuration.
 *
 * API_BASE  Your deployed Cloudflare Worker URL. No trailing slash.
 *           Example: https://tr-api.karen.workers.dev
 *           While this is empty the app CANNOT authenticate anyone.
 *
 * DEMO_MODE Leave false for production.
 *           true + empty API_BASE runs the UI on-device for previewing only,
 *           which signs every visitor in as the administrator. Never enable
 *           this on a site real members can reach.
 */
window.TR_CONFIG = {
  API_BASE: 'https://tr-api.morning-wave-675d.workers.dev',
  DEMO_MODE: false
};
