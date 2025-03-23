/**
 * Error Utilities for MessX Client
 * Provides standardized error handling throughout the application
 */

const ErrorUtils = {
  /**
   * Log an error with standardized format
   * @param {string} context - Where the error occurred
   * @param {Error|string} error - The error object or message
   * @param {Object} data - Optional additional data
   */
  logError(context, error, data = {}) {
    const errorObj = {
      timestamp: new Date().toISOString(),
      context,
      message: error instanceof Error ? error.message : error,
      stack: error instanceof Error ? error.stack : null,
      data,
    };

    console.error(`[${errorObj.timestamp}] ${context}:`, errorObj);

    // In a production app, you might send this to a server error logging service
  },

  /**
   * Handle API errors consistently
   * @param {Object} response - API response
   * @param {string} operation - Operation being performed
   * @param {Function} showToast - Function to display toast messages
   * @param {Function} showModal - Function to display modal errors
   * @returns {boolean} - True if there was no error, false if error was handled
   */
  handleApiError(response, operation, showToast, showModal) {
    if (!response) {
      showModal(
        "Connection Error",
        "Failed to connect to the server. Please check your internet connection."
      );
      return false;
    }

    const errorOpcode = response.error_opcode;
    const opcode = response.opcode;

    if (!errorOpcode) {
      return true;
    }

    // Log the error
    this.logError(
      `API Error in ${operation}`,
      `Error code: 0x${errorOpcode.toString(16)}`,
      { opcode, errorOpcode, operation }
    );

    // Get user-friendly error message from API
    const errorMessage = API.getErrorMessage(
      opcode.toString(16),
      errorOpcode.toString(16)
    );

    // Authentication errors get shown in modal
    if (errorOpcode === 0x48 || errorOpcode === 0x03) {
      // Special case for invalid credentials during login
      if (errorOpcode === 0x03 && opcode === 0x00) {
        showToast("Invalid username or password", "error");
        return false;
      }

      showModal("Authentication Error", errorMessage);
      return false;
    }

    // Generic handling for other errors
    showToast(errorMessage, "error");
    return false;
  },
};
