// Global variables to hold auth info
let authToken = null;
let currentUsername = null;

// Cache DOM elements
const authContainer = document.getElementById("authContainer");
const mainContainer = document.getElementById("mainContainer");
const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");
const authTabs = document.querySelectorAll(".auth-tab");
const currentUsernameSpan = document.getElementById("currentUsername");
const logoutBtn = document.getElementById("logoutBtn");

// Modals
const createChatModal = document.getElementById("createChatModal");
const createChatForm = document.getElementById("createChatForm");
const cancelCreateChatBtn = document.getElementById("cancelCreateChatBtn");

const addUserModal = document.getElementById("addUserModal");
const addUserForm = document.getElementById("addUserForm");
const cancelAddUserBtn = document.getElementById("cancelAddUserBtn");

const pokeUserModal = document.getElementById("pokeUserModal");
const pokeUserForm = document.getElementById("pokeUserForm");
const cancelPokeBtn = document.getElementById("cancelPokeBtn");

// New DOM elements and variables
const chatList = document.getElementById("chatList");
const currentChatName = document.getElementById("currentChatName");
const messageInput = document.getElementById("messageInput");
const sendMessageBtn = document.getElementById("sendMessageBtn");

const manageRolesBtn = document.getElementById("manageRolesBtn");
const roleManagementModal = document.getElementById("roleManagementModal");
const createRoleForm = document.getElementById("createRoleForm");
const assignRoleForm = document.getElementById("assignRoleForm");
const removeRoleForm = document.getElementById("removeRoleForm");

const chatSettingsBtn = document.getElementById("chatSettingsBtn");
const chatSettingsModal = document.getElementById("chatSettingsModal");
const removeUserBtn = document.getElementById("removeUserBtn");
const leaveChatBtn = document.getElementById("leaveChatBtn");
const deleteChatBtn = document.getElementById("deleteChatBtn");
const messagesContainer = document.getElementById("messagesContainer");
const pokeBtn = document.getElementById("pokeBtn");

// Modals
const editMessageModal = document.getElementById("editMessageModal");
const editMessageForm = document.getElementById("editMessageForm");
const cancelEditMessageBtn = document.getElementById("cancelEditMessageBtn");

// Variables
let currentChat = null;
let currentMessageId = null;
let messagePollingInterval = null; // Store interval reference for cleanup
const POLLING_INTERVAL = 2000; // Poll every 2 seconds instead of 3
let lastVisibleMessageId = null; // Track the last visible message for read receipts
const readReceiptsModal = document.getElementById("readReceiptsModal");
let pendingReadMessages = []; // Cache messages that need to be marked as read
let lastReadBatchTime = 0; // Track when we last sent a batch of read receipts

// Add this debounce function at the top of the file
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Add near the top of app.js
let tokenRefreshInterval = null;

function startTokenRefresher() {
  // Clear any existing interval
  if (tokenRefreshInterval) {
    clearInterval(tokenRefreshInterval);
  }

  // Refresh token every 6 hours
  tokenRefreshInterval = setInterval(async () => {
    try {
      if (!authToken) return;

      console.log("Attempting to refresh token...");
      const result = await API.refreshToken(authToken);

      if (result.opcode === 0x00 && result.new_token) {
        // Update token
        authToken = result.new_token;
        localStorage.setItem("authToken", authToken);
        localStorage.setItem("tokenTimestamp", Date.now().toString());
        console.log("Token refreshed successfully");
      } else {
        console.error("Failed to refresh token:", result);
        // If token refresh failed, suggest login
        showToast(
          "Your session may have expired. Please log in again.",
          "warning"
        );
      }
    } catch (error) {
      console.error("Token refresh error:", error);
    }
  }, 6 * 60 * 60 * 1000); // 6 hours
}

// Add token restoration from localStorage
document.addEventListener("DOMContentLoaded", () => {
  const savedToken = localStorage.getItem("authToken");
  const savedUsername = localStorage.getItem("username");

  if (savedToken && savedUsername) {
    console.log("Restoring session from saved token");
    authToken = savedToken;
    currentUsername = savedUsername;
    currentUsernameSpan.innerText = savedUsername;

    // Show main container
    authContainer.classList.add("hidden");
    mainContainer.classList.remove("hidden");

    // Start token refresher
    startTokenRefresher();

    // Load chats
    loadChats();
  }
});

// Initialize buttons from DOM - place this near the top with other DOM elements
const generateInviteLinkBtn = document.getElementById("generateInviteLinkBtn");

// Add this near the top with your other DOM element references
const toggleSidebarBtn = document.getElementById("toggleSidebarBtn");

// Add this near the top with your other DOM element references, after the other elements
const sidebar = document.querySelector(".sidebar");

// Create an overlay element to detect clicks outside the sidebar
const sidebarOverlay = document.createElement("div");
sidebarOverlay.className = "sidebar-overlay";
document.body.appendChild(sidebarOverlay);

// Add toggle sidebar functionality
toggleSidebarBtn.addEventListener("click", () => {
  sidebar.classList.toggle("visible");
  sidebarOverlay.classList.toggle("visible");
});

// Close sidebar when clicking on overlay or selecting a chat
sidebarOverlay.addEventListener("click", () => {
  sidebar.classList.remove("visible");
  sidebarOverlay.classList.remove("visible");
});

// Utility function to show/hide modals
function openModal(modal) {
  modal.classList.add("active");
}
function closeModal(modal) {
  modal.classList.remove("active");
}

// Switch between login and register tabs
authTabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    authTabs.forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    if (tab.dataset.tab === "login") {
      loginForm.classList.remove("hidden");
      registerForm.classList.add("hidden");
    } else {
      loginForm.classList.add("hidden");
      registerForm.classList.remove("hidden");
    }
  });
});

// Login form submission with enhanced error handling
loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("loginUsername").value;
  const password = document.getElementById("loginPassword").value;

  if (!username || !password) {
    showToast("Username and password are required", "error");
    return;
  }

  try {
    showToast("Logging in...", "info");
    const passwordHash = await sha256(password);
    const data = await API.login(username, passwordHash);

    // console.log("Login response:", data); // Debug logging

    if (data.opcode === 0x01 && data.authentication_token) {
      // Simply store the token directly
      authToken = data.authentication_token;

      // Also store in localStorage as a backup with timestamp
      localStorage.setItem("authToken", authToken);
      localStorage.setItem("username", username);
      localStorage.setItem("tokenTimestamp", Date.now().toString());

      currentUsername = username;
      currentUsernameSpan.innerText = username;
      authContainer.classList.add("hidden");
      mainContainer.classList.remove("hidden");
      loadChats();
      showToast(`Welcome back, ${username}!`, "success");

      // Start token refresher
      startTokenRefresher();

      // Check if there's a pending invite link
      const pendingInviteLink = localStorage.getItem("pendingInviteLink");
      if (pendingInviteLink) {
        // Process the invite link
        try {
          await joinChatViaInviteLink(pendingInviteLink);
          localStorage.removeItem("pendingInviteLink");
        } catch (error) {
          console.error("Error processing invite link:", error);
        }
      }
    } else if (data.error_opcode) {
      // Handle specific error cases
      const errorOpcode = data.error_opcode;
      const opcode = data.opcode;

      if (errorOpcode === 0x03 && opcode === 0x00) {
        showToast("Invalid username or password", "error");
        document.getElementById("loginPassword").focus();
        document.getElementById("loginPassword").select();
      } else if (errorOpcode === 0x45) {
        // Special handling for server errors which might be quota issues
        showErrorModal(
          "Server Error",
          "The server encountered a problem (possibly a quota limit). Please try again in a few minutes."
        );
      } else {
        // Get user-friendly error message from API
        const errorMessage = API.getErrorMessage(
          opcode.toString(16),
          errorOpcode.toString(16)
        );
        showErrorModal("Authentication Error", errorMessage);
      }
    } else {
      // Fallback error for unexpected response format
      showErrorModal(
        "Authentication Error",
        "Server response was invalid. Please try again."
      );
    }
  } catch (error) {
    console.error("Login failed", error);
    showErrorModal(
      "Connection Error",
      "Failed to connect to the server. Please check your internet connection and try again."
    );
  }
});

// Register form submission
registerForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("registerUsername").value;
  const password = document.getElementById("registerPassword").value;
  const confirmPassword = document.getElementById("confirmPassword").value;

  if (password !== confirmPassword) {
    showToast("Passwords do not match!", "error");
    return;
  }

  // Add stronger password validation
  if (password.length < 8) {
    showToast("Password must be at least 8 characters", "error");
    return;
  }

  // Check for password complexity - require at least one number and one special character
  const hasNumber = /\d/.test(password);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  if (!hasNumber || !hasSpecial) {
    showToast(
      "Password must contain at least one number and one special character",
      "error"
    );
    return;
  }

  try {
    showToast("Creating account...", "info");
    const passwordHash = await sha256(password);
    const data = await API.createAccount(username, passwordHash);

    console.log("Account creation response:", data); // Debug log

    // Direct check for success opcode instead of using handleApiError
    if (data.opcode === 0x00) {
      // Generate encryption keys explicitly here
      try {
        const keyData = await AuthUtils.generateAndStoreUserKeys();
        console.log("Generated new encryption keys for user", username);

        // Continue with the success flow
        showToast("Account created successfully! Please log in.", "success");
        // Switch to login tab
        authTabs.forEach((t) => t.classList.remove("active"));
        document
          .querySelector('.auth-tab[data-tab="login"]')
          .classList.add("active");
        loginForm.classList.remove("hidden");
        registerForm.classList.add("hidden");

        // Pre-fill username for convenience
        document.getElementById("loginUsername").value = username;
      } catch (keyError) {
        console.error("Failed to generate encryption keys:", keyError);
        showErrorModal(
          "Encryption Setup Error",
          "Your account was created, but we couldn't set up encryption. Please try logging in."
        );

        // Still switch to login tab despite the encryption error
        authTabs.forEach((t) => t.classList.remove("active"));
        document
          .querySelector('.auth-tab[data-tab="login"]')
          .classList.add("active");
        loginForm.classList.remove("hidden");
        registerForm.classList.add("hidden");
        document.getElementById("loginUsername").value = username;
      }
    } else if (data.error_opcode) {
      // Handle specific error codes
      if (data.error_opcode === 0x01) {
        showToast("Username already taken. Please choose another.", "error");
      } else if (data.error_opcode === 0x02) {
        showToast("Invalid password format.", "error");
      } else {
        // Get user-friendly error message from API
        const errorMessage = API.getErrorMessage(
          data.opcode.toString(16),
          data.error_opcode.toString(16)
        );
        showToast(errorMessage, "error");
      }
    } else {
      // Fallback for unknown errors
      showToast("An unexpected error occurred. Please try again.", "error");
    }
  } catch (error) {
    console.error("Registration error", error);
    showErrorModal(
      "Connection Error",
      "Failed to connect to the server. Please check your internet connection and try again."
    );
  }
});

// Logout button
logoutBtn.addEventListener("click", () => {
  authToken = null;
  currentUsername = null;
  mainContainer.classList.add("hidden");
  authContainer.classList.remove("hidden");

  // Stop message polling when logging out
  stopMessagePolling();

  // Clear any other app state
  currentChat = null;
  currentMessageId = null;
});

// Create Chat modal handling
document
  .getElementById("createChatBtn")
  .addEventListener("click", () => openModal(createChatModal));
cancelCreateChatBtn.addEventListener("click", () =>
  closeModal(createChatModal)
);
createChatForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const chatName = document.getElementById("chatName").value;
  if (chatName.length < 3) {
    showToast("Chat name must be at least 3 characters", "error");
    return;
  }

  try {
    showToast("Creating chat...", "info");
    const data = await API.createChat(authToken, chatName);

    if (handleApiError(data)) {
      showToast("Chat created successfully", "success");
      closeModal(createChatModal);
      document.getElementById("chatName").value = "";
      loadChats();
    }
  } catch (error) {
    console.error("Create chat error", error);
    showErrorModal(
      "Connection Error",
      "Failed to connect to the server. Please check your internet connection and try again."
    );
  }
});

// Add User modal handling
document
  .getElementById("addUserBtn")
  .addEventListener("click", () => openModal(addUserModal));
cancelAddUserBtn.addEventListener("click", () => closeModal(addUserModal));
addUserForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const chatName = currentChatName.innerText; // assuming currentChatName shows the active chat
  const usernameToAdd = document.getElementById("addUsername").value;
  try {
    const data = await API.addUserToChat(authToken, chatName, usernameToAdd);
    if (data.opcode === 0x00) {
      alert(`User ${usernameToAdd} added successfully`);
      closeModal(addUserModal);
    } else {
      alert("Error adding user");
    }
  } catch (error) {
    console.error("Add user error", error);
  }
});

// Poke User modal handling
document
  .getElementById("pokeBtn")
  .addEventListener("click", () => openModal(pokeUserModal));
cancelPokeBtn.addEventListener("click", () => closeModal(pokeUserModal));
pokeUserForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const chatName = currentChatName.innerText;
  const usernameToPoke = document.getElementById("pokeUsername").value.trim();

  if (!usernameToPoke) {
    showToast("Please enter a username to poke", "error");
    return;
  }

  try {
    showToast(`Poking ${usernameToPoke}...`, "info");
    const data = await API.pokeUser(authToken, chatName, usernameToPoke);

    if (data.opcode === 0x00) {
      showToast(`Poke sent to ${usernameToPoke}!`, "success");
      document.getElementById("pokeUsername").value = ""; // Clear the input field
      closeModal(pokeUserModal);
      // Refresh messages to see the poke
      loadChatMessages(chatName);
    } else {
      // Handle specific error codes from the server
      const errorCode = data.error_opcode;
      if (errorCode === 0x38) {
        showToast("Invalid chat name", "error");
      } else if (errorCode === 0x39) {
        showToast(
          `Cannot poke ${usernameToPoke}. User may not exist, is not in this chat, or has blocked you.`,
          "error"
        );
      } else if (errorCode === 0x49) {
        showToast("You must be a member of the chat to poke users", "error");
      } else {
        showToast(
          `Error sending poke: code ${errorCode.toString(16)}`,
          "error"
        );
      }
    }
  } catch (error) {
    console.error("Poke error", error);
    showToast("Network error while sending poke", "error");
  }
});

// (Optional) Common modal close handler for buttons with "close-modal" class
document.querySelectorAll(".close-modal").forEach((btn) => {
  btn.addEventListener("click", () => {
    btn.closest(".modal").classList.remove("active");
  });
});

// Simple SHA256 using SubtleCrypto (for modern browsers)
async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Add a new container for pinned messages
const pinnedMessagesContainer = document.createElement("div");
pinnedMessagesContainer.id = "pinnedMessagesContainer";
pinnedMessagesContainer.className = "pinned-messages-container";
messagesContainer.parentNode.insertBefore(
  pinnedMessagesContainer,
  messagesContainer
);

// Add the missing hidePinnedMessage function first
function hidePinnedMessage() {
  // Clear the pinned messages container
  pinnedMessagesContainer.innerHTML = "";
  pinnedMessagesContainer.style.display = "none";
}

// Add a displayPinnedMessage function if it's also missing
function displayPinnedMessage(message) {
  pinnedMessagesContainer.innerHTML = "";
  pinnedMessagesContainer.style.display = "block";

  const pinnedElement = createMessageElement(message, true);
  pinnedMessagesContainer.appendChild(pinnedElement);
}

// New function to batch process read receipts
async function processPendingReadReceipts() {
  if (pendingReadMessages.length === 0 || !currentChat || !authToken) return;

  // Only process if we have messages and at least 1 second has passed since the last batch
  const now = Date.now();
  if (now - lastReadBatchTime < 1000) return;

  try {
    // Create a copy of the current pending messages and clear the original array
    const messagesToProcess = [...pendingReadMessages];
    pendingReadMessages = [];
    lastReadBatchTime = now;

    if (messagesToProcess.length > 0) {
      console.log(`Processing ${messagesToProcess.length} read receipts`);

      // Make a single API call with all message IDs
      const data = await API.markMessagesAsRead(
        authToken,
        currentChat,
        messagesToProcess
      );

      if (data.opcode !== 0x00) {
        console.error("Error marking messages as read:", data.error_opcode);
        // If there's an error, don't add the messages back to the queue
      }
    }
  } catch (error) {
    console.error("Error processing read receipts:", error);
  }
}

// Add a recurring timer to process read receipts
setInterval(processPendingReadReceipts, 1500); // Process batches every 1.5 seconds

// Fix the loadChatMessages function to avoid showing "loading" for minor updates
async function updateMessagesWithoutLoading(chatName, actionType) {
  try {
    const data = await API.getMessages(
      authToken,
      chatName,
      currentMessageLimit
    );

    if (data.opcode === 0x00) {
      const messages = data.messages || [];
      // Don't show loading indicator, just update in place
      renderMessages(messages, actionType === "send");

      // Update pinned message if exists
      if (data.pinned_message) {
        displayPinnedMessage(data.pinned_message);
      } else {
        hidePinnedMessage();
      }
    }
  } catch (error) {
    console.error("Error updating messages:", error);
  }
}

// Update loadChatMessages to properly pass the scroll parameter
async function loadChatMessages(chatName, scrollToBottom = false) {
  try {
    // Reset message limit when loading a new chat
    currentMessageLimit = MESSAGE_BATCH_SIZE;

    messagesContainer.innerHTML =
      '<div class="loading">Loading messages...</div>';

    const data = await API.getMessages(
      authToken,
      chatName,
      currentMessageLimit
    );

    if (data.opcode === 0x00) {
      const messages = data.messages || [];

      if (messages.length === 0) {
        messagesContainer.innerHTML = `
          <div class="empty-state">
            <p>No messages yet. Start the conversation!</p>
          </div>`;
      } else {
        // Use the updated renderMessages function with correct scrollToBottom parameter
        renderMessages(messages, scrollToBottom);

        // Update last visible message for read receipts
        if (messages.length > 0) {
          lastVisibleMessageId = messages[messages.length - 1].message_id;
        }
      }

      // Display pinned message if exists
      if (data.pinned_message) {
        displayPinnedMessage(data.pinned_message);
      } else {
        hidePinnedMessage();
      }
    } else {
      // Handle API error
      messagesContainer.innerHTML = `
        <div class="error-state">
          <p>Failed to load messages. ${API.getErrorMessage(
            0x11,
            data.error_opcode
          )}</p>
        </div>`;
    }
  } catch (error) {
    console.error("Error loading messages", error);
    messagesContainer.innerHTML = `
      <div class="error-state">
        <p>Error loading messages: ${error.message}</p>
      </div>`;
  }
}

// Replace the renderMessages function with this consistent implementation
function renderMessages(messages, scrollToBottom = false) {
  // Clear existing messages first
  messagesContainer.innerHTML = "";

  // If we have enough messages to warrant a "load more" button
  if (messages.length >= currentMessageLimit) {
    // Add a load more button at the top
    messagesContainer.appendChild(createLoadMoreButton());
  }

  // Sort messages chronologically (oldest first)
  // This ensures consistent order regardless of how they come from the API
  messages.sort((a, b) => {
    const timeA = new Date(a.timestamp);
    const timeB = new Date(b.timestamp);
    return timeA - timeB; // Ascending order (oldest first)
  });

  // Add messages in chronological order (oldest first, newest last)
  messages.forEach((msg) => {
    const messageElement = createMessageElement(msg);
    messagesContainer.appendChild(messageElement);
  });

  // Scroll to bottom to show newest messages
  if (scrollToBottom) {
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }
}

// Helper function to create message elements
function createMessageElement(msg, isPinnedDisplay = false) {
  const div = document.createElement("div");

  // Check if this is a blocked message
  if (msg.is_blocked) {
    div.className = "message blocked";
    div.innerHTML = `
      <div class="blocked-message-content">Message unavailable</div>
      <div class="message-timestamp">${msg.timestamp || ""}</div>
    `;
    return div;
  }

  // Check for system messages (type 0x02)
  if (msg.type === 0x02) {
    div.className = "message system";
    div.innerHTML = `
      <div class="message-content">${msg.content}</div>
      <div class="message-timestamp">${msg.timestamp || ""}</div>
    `;
    return div;
  }

  div.className =
    msg.type === 0x01
      ? "message poke"
      : "message " + (msg.sender === currentUsername ? "outgoing" : "incoming");

  // Add pinned class if the message is pinned
  if (msg.pinned) {
    div.classList.add("pinned");
  }

  // Store message ID and other data as attributes for editing and deletion
  div.dataset.messageId = msg.id;
  div.dataset.senderUid = msg.sender_uid;
  div.dataset.senderUsername = msg.sender;

  // Format roles display if the sender has any roles
  let rolesDisplay = "";
  if (msg.sender_roles && msg.sender_roles.length > 0) {
    const rolesList = msg.sender_roles
      .map((role) => `<span class="role-badge">${role}</span>`)
      .join("");
    rolesDisplay = `<div class="sender-roles">${rolesList}</div>`;
  }

  // Determine what name to display (custom display name or original sender name)
  const displayName = msg.display_name || msg.sender;

  if (msg.type === 0x01) {
    // Poke message with improved styling
    div.innerHTML = `
      <div class="poke-message">
        <span class="material-icons poke-icon">notifications_active</span>
        <div class="message-content">${msg.content}</div>
      </div>
      <div class="message-timestamp">${msg.timestamp || ""}</div>
    `;
  } else {
    // Normal message
    div.innerHTML = `
      <div class="message-sender">
        ${displayName}
        ${
          msg.display_name
            ? `<span class="custom-name-indicator" title="Custom name for ${msg.sender}">✎</span>`
            : ""
        }
        ${rolesDisplay}
      </div>
      <div class="message-content">${handleEncryptedMessage(msg.content)}</div>
      <div class="message-footer">
        ${
          msg.edited
            ? '<span class="message-edited-indicator">(edited)</span>'
            : ""
        }
        ${
          msg.pinned && !isPinnedDisplay
            ? '<span class="material-icons pin-icon">push_pin</span>'
            : ""
        }
        <div class="message-timestamp">${msg.timestamp || ""}</div>
      </div>`;
  }

  // Only show edit/delete options for your own messages or if you're in pinned display area
  if (!isPinnedDisplay) {
    const messageActions = document.createElement("div");
    messageActions.className = "message-actions-menu";

    // Determine which buttons to show based on message ownership
    let actionButtons = "";

    // If it's your message, you can edit and delete it
    if (msg.sender === currentUsername) {
      actionButtons += `
        <button class="edit-btn" title="Edit Message">
          <span class="material-icons">edit</span>
        </button>
        <button class="delete-btn" title="Delete Message">
          <span class="material-icons">delete</span>
        </button>
      `;
    }

    // Everyone can pin/unpin messages
    const pinButtonText = msg.pinned ? "Unpin" : "Pin";
    actionButtons += `
      <button class="pin-btn" title="${pinButtonText} Message">
        <span class="material-icons">${
          msg.pinned ? "push_pin_off" : "push_pin"
        }</span>
      </button>
    `;

    messageActions.innerHTML = actionButtons;
    div.appendChild(messageActions);

    // Add event listeners to buttons
    const editBtn = messageActions.querySelector(".edit-btn");
    if (editBtn) {
      editBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        currentMessageId = msg.id;
        document.getElementById("editMessageInput").value = msg.content;
        openModal(editMessageModal);
      });
    }

    const deleteBtn = messageActions.querySelector(".delete-btn");
    if (deleteBtn) {
      deleteBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        if (confirm("Are you sure you want to delete this message?")) {
          console.log("Deleting message from action button:", msg.id);
          deleteMessage(msg.id);
        }
      });
    }

    const pinBtn = messageActions.querySelector(".pin-btn");
    if (pinBtn) {
      pinBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        const isPinned = msg.pinned;
        pinMessage(msg.id, isPinned); // If already pinned, unpin it
      });
    }
  } else {
    // Add an unpin button to the pinned message
    const unpinBtn = document.createElement("button");
    unpinBtn.className = "unpin-btn";
    unpinBtn.innerHTML = '<span class="material-icons">push_pin_off</span>';
    unpinBtn.title = "Unpin Message";
    div.appendChild(unpinBtn);

    unpinBtn.addEventListener("click", () => {
      pinMessage(msg.id, true); // Pass true to indicate unpinning
    });
  }

  // Only add read receipt indicators to outgoing messages
  if (msg.sender === currentUsername && !isPinnedDisplay) {
    const readStatus = document.createElement("div");
    readStatus.className = "message-read-status";

    // Determine the status icon based on message state
    let statusIcon = "done"; // Default: sent
    let statusText = "Sent";
    let statusClass = "sent";

    if (msg.delivered_to && msg.delivered_to.length > 0) {
      statusIcon = "done_all";
      statusText = "Delivered";
      statusClass = "delivered";

      if (msg.read_by && msg.read_by.length > 0) {
        statusClass = "read";
        statusText = "Read";
      }
    }

    readStatus.innerHTML = `
      <span class="material-icons read-indicator ${statusClass}" title="Click for details">${statusIcon}</span>
      <span class="read-status-text">${statusText}</span>
    `;

    // Make the status clickable to show detailed read receipts
    readStatus.addEventListener("click", (e) => {
      e.stopPropagation();
      showReadReceipts(msg.id);
    });

    div.appendChild(readStatus);
  }

  return div;
}

// Update the pinMessage function to use the new update method
async function pinMessage(messageId, shouldUnpin = false) {
  if (!currentChat) return;
  try {
    // Determine if we need to pin or unpin
    let data;
    if (shouldUnpin) {
      data = await API.unpinMessage(authToken, currentChat, messageId);
    } else {
      data = await API.pinMessage(authToken, currentChat, messageId);
    }

    if (handleApiError(data)) {
      // Show success toast
      const message = shouldUnpin ? "Message unpinned" : "Message pinned";
      showToast(message, "success");
      // Use the non-loading update method instead
      updateMessagesWithoutLoading(currentChat, "pin");
    }
  } catch (error) {
    console.error(
      `Error ${shouldUnpin ? "unpinning" : "pinning"} message`,
      error
    );
    showErrorModal(
      "Connection Error",
      `Failed to ${
        shouldUnpin ? "unpin" : "pin"
      } message. Please check your connection and try again.`
    );
  }
}

// Improved helper function to delete a message with better error handling and animation
async function deleteMessage(messageId) {
  if (!currentChat) {
    showToast("Select a chat first", "error");
    return;
  }

  try {
    // Find the message element in the DOM
    const messageElement = document.querySelector(
      `.message[data-message-id="${messageId}"]`
    );
    if (!messageElement) {
      console.warn("Message element not found in DOM");
      showToast("Message could not be found", "error");
      return;
    }

    // Apply the deleting animation class before making the API call
    messageElement.classList.add("deleting");

    // Show subtle toast
    showToast("Deleting message...", "info");

    console.log(
      "Sending request to delete message:",
      messageId,
      "in chat:",
      currentChat
    );

    // Make API call to delete the message
    const data = await API.deleteMessage(authToken, currentChat, messageId);

    if (data.opcode === 0x00) {
      // Wait for animation to complete before removing from DOM
      setTimeout(() => {
        if (messageElement.parentNode) {
          messageElement.parentNode.removeChild(messageElement);
        }

        showToast("Message deleted successfully", "success");
      }, 600); // Match this to the animation duration
    } else {
      // If there was an error, remove the animation class to revert the message
      messageElement.classList.remove("deleting");

      console.error("Delete error response:", data);
      const errorCode = data.error_opcode;
      if (errorCode === 0x22) {
        showToast("Invalid chat name", "error");
      } else if (errorCode === 0x23) {
        showToast("Invalid message ID", "error");
      } else if (errorCode === 0x49) {
        showToast("You don't have permission to delete this message", "error");
      } else {
        showToast(
          `Error deleting message: code ${errorCode.toString(16)}`,
          "error"
        );
      }
    }
  } catch (error) {
    // Make sure to remove the animation if there's an exception
    const messageElement = document.querySelector(
      `.message[data-message-id="${messageId}"]`
    );
    if (messageElement) {
      messageElement.classList.remove("deleting");
    }

    console.error("Error deleting message:", error);
    showToast("Network error while deleting message", "error");
  }
}

// Add context menu for messages with display name change option
messagesContainer.addEventListener("contextmenu", (e) => {
  e.preventDefault();
  const messageDiv = e.target.closest(".message");
  if (!messageDiv) return;

  // Get information about the message
  const messageId = messageDiv.dataset.messageId;
  const senderUid = messageDiv.dataset.senderUid;
  const senderUsername = messageDiv.dataset.senderUsername;

  // Don't show context menu for system messages or if we don't have the required data
  if (!messageId || !senderUid || !senderUsername) {
    console.warn("Message data not found");
    return;
  }

  // Determine if this is the user's own message
  const isSender = messageDiv.classList.contains("outgoing");

  // Show custom context menu with options
  const contextMenu = document.createElement("div");
  contextMenu.className = "context-menu";
  contextMenu.style.position = "absolute";
  contextMenu.style.left = `${e.pageX}px`;
  contextMenu.style.top = `${e.pageY}px`;

  // Don't allow changing display name of your own messages
  let menuItems = `
    <div class="context-menu-item" data-action="pin">
      <span class="material-icons">push_pin</span> 
      ${
        messageDiv.classList.contains("pinned")
          ? "Unpin Message"
          : "Pin Message"
      }
    </div>
  `;

  // Show edit/delete for user's own messages
  if (isSender) {
    menuItems += `
      <div class="context-menu-item" data-action="edit">
        <span class="material-icons">edit</span> Edit Message
      </div>
      <div class="context-menu-item" data-action="delete">
        <span class="material-icons">delete</span> Delete Message
      </div>
    `;
  } else {
    // Only add display name option for other people's messages
    menuItems += `
      <div class="context-menu-item" data-action="changeDisplayName">
        <span class="material-icons">badge</span> Change Display Name
      </div>
      <div class="context-menu-item" data-action="blockUser">
        <span class="material-icons">block</span> Block User
      </div>
    `;
  }

  contextMenu.innerHTML = menuItems;
  document.body.appendChild(contextMenu);

  // Handle context menu item clicks
  contextMenu.addEventListener("click", async (e) => {
    const actionElement = e.target.closest(".context-menu-item");
    if (!actionElement) return;

    const action = actionElement.dataset.action;

    if (action === "pin") {
      const isPinned = messageDiv.classList.contains("pinned");
      pinMessage(messageId, isPinned); // If already pinned, unpin it
    } else if (action === "delete") {
      if (confirm("Are you sure you want to delete this message?")) {
        console.log("Deleting message:", messageId);
        // Close the context menu before starting delete animation
        document.body.removeChild(contextMenu);
        await deleteMessage(messageId);
        return; // Return early since we've already removed the context menu
      }
    } else if (action === "edit") {
      currentMessageId = messageId;
      const messageContent =
        messageDiv.querySelector(".message-content").innerText;
      document.getElementById("editMessageInput").value = messageContent;
      openModal(editMessageModal);
    } else if (action === "changeDisplayName") {
      const currentDisplayName = messageDiv
        .querySelector(".message-sender")
        .childNodes[0].textContent.trim();
      const newDisplayName = prompt(
        `Enter a custom display name for ${senderUsername}:`,
        currentDisplayName
      );
      if (newDisplayName && newDisplayName.trim()) {
        changeUserDisplayName(senderUsername, newDisplayName.trim());
      }
    } else if (action === "blockUser") {
      if (
        confirm(
          `Are you sure you want to block ${senderUsername}? You won't see their messages anymore.`
        )
      ) {
        blockUser(senderUsername);
      }
    }

    // Remove context menu
    document.body.removeChild(contextMenu);
  });

  // Close context menu when clicking elsewhere
  document.addEventListener("click", function closeContextMenu() {
    if (document.body.contains(contextMenu)) {
      document.body.removeChild(contextMenu);
    }
    document.removeEventListener("click", closeContextMenu);
  });
});

// Function to change a user's display name
async function changeUserDisplayName(username, displayName) {
  if (!currentChat) {
    showToast("Select a chat first", "error");
    return;
  }
  try {
    const data = await API.changeDisplayName(
      authToken,
      currentChat,
      username,
      displayName
    );
    if (data.opcode === 0x00) {
      showToast(
        `Display name for ${username} changed to "${displayName}"`,
        "success"
      );
      loadChatMessages(currentChat); // Reload to show updated names
    } else {
      const errorCode = data.error_opcode;
      if (errorCode === 0x12) {
        showToast("Invalid chat name", "error");
      } else if (errorCode === 0x13) {
        showToast("Invalid display name or user not found", "error");
      } else if (errorCode === 0x49) {
        showToast(
          "You don't have permission to change display names in this chat",
          "error"
        );
      } else {
        showToast(`Error changing display name: code ${errorCode}`, "error");
      }
    }
  } catch (error) {
    console.error("Error changing display name", error);
    showToast("Network error while changing display name", "error");
  }
}

// Utility: load chats
async function loadChats() {
  try {
    const data = await API.getChats(authToken);
    if (data.opcode === 0x00) {
      chatList.innerHTML = "";
      if (!data.chats || data.chats.length === 0) {
        chatList.innerHTML = `<div class="empty-state">No chats yet. Create one!</div>`;
        return;
      }

      // Sort chats alphabetically for easier finding
      const sortedChats = [...data.chats].sort((a, b) =>
        a.name.localeCompare(b.name)
      );

      sortedChats.forEach((chat) => {
        const chatItem = document.createElement("div");
        chatItem.className = "chat-item";
        // Add a special class for creator-owned chats
        if (chat.is_owner) {
          chatItem.classList.add("owner");
        }
        chatItem.innerText = chat.name;

        // If this is the current chat, mark it as active
        if (currentChat && chat.name === currentChat) {
          chatItem.classList.add("active");
        }

        chatList.appendChild(chatItem);
      });
    } else {
      console.error("Failed to load chats:", data.error_opcode);
      // Simple fallback if the API isn't available: show create chat button
      chatList.innerHTML = `<div class="empty-state">Use the + button to create a chat</div>`;
    }
  } catch (error) {
    console.error("Error loading chats", error);
    chatList.innerHTML = `<div class="empty-state">Failed to load chats. Check your connection.</div>`;
  }
}

// Update the polling function to use renderMessages
// Update the polling function to use renderMessages correctly
function startMessagePolling(chatName) {
  stopMessagePolling(); // Clear any existing polling

  messagePollingInterval = setInterval(async () => {
    try {
      if (!currentChat) return;

      const data = await API.getMessages(
        authToken,
        currentChat,
        currentMessageLimit
      );

      if (data.opcode === 0x00) {
        const messages = data.messages || [];

        // Get the currently displayed messages
        const currentMessageIds = Array.from(
          document.querySelectorAll(".message")
        ).map((el) => el.dataset.messageId);

        // Check if messages have changed
        const messageChanged =
          messages.some((msg) => !currentMessageIds.includes(msg.id)) ||
          currentMessageIds.some(
            (id) => !messages.find((msg) => msg.id === id)
          );

        // Only re-render if the messages have changed
        if (messageChanged) {
          // Remember scroll position to see if we're scrolled to bottom
          const isAtBottom =
            messagesContainer.scrollHeight - messagesContainer.scrollTop <=
            messagesContainer.clientHeight + 50;

          // Render with the updated messages - scroll to bottom only if we were already at bottom
          renderMessages(messages, isAtBottom);

          // Check for new pinned message
          if (data.pinned_message) {
            displayPinnedMessage(data.pinned_message);
          } else {
            hidePinnedMessage();
          }
        }
      } else if (data.error_opcode === 0x17) {
        // Chat not found, it might have been deleted
        showDeletedChatEffect();
        stopMessagePolling();
      }
    } catch (error) {
      console.error("Error polling messages:", error);
    }
  }, POLLING_INTERVAL);
}
// Stop polling for messages
function stopMessagePolling() {
  if (messagePollingInterval) {
    clearInterval(messagePollingInterval);
    messagePollingInterval = null;
    console.log("Stopped message polling");
  }
}

// Add effect for deleted chat
function showDeletedChatEffect() {
  // Create overlay effect
  const overlay = document.createElement("div");
  overlay.className = "deleted-chat-overlay";

  // Add the deleted chat message
  const messageBox = document.createElement("div");
  messageBox.className = "deleted-chat-message";
  messageBox.innerHTML = `
    <span class="material-icons">delete_forever</span>
    <h3>This chat has been deleted</h3>
    <p>The chat owner has deleted this conversation.</p>
    <button class="btn primary close-deleted-chat">OK</button>
  `;

  overlay.appendChild(messageBox);
  document.body.appendChild(overlay);

  // Add event listener to close button
  const closeBtn = overlay.querySelector(".close-deleted-chat");
  closeBtn.addEventListener("click", () => {
    document.body.removeChild(overlay);
    // Reset current chat
    currentChat = null;
    currentChatName.innerText = "Select a chat";
    messageInput.disabled = true;
    sendMessageBtn.disabled = true;
    pokeBtn.disabled = true;
    // Stop polling and reload the chat list
    stopMessagePolling();
    loadChats();
  });

  // Auto-close after 10 seconds
  setTimeout(() => {
    if (document.body.contains(overlay)) {
      document.body.removeChild(overlay);
    }
  }, 10000);
}

// When a chat item is clicked, select the chat and enable messaging
chatList.addEventListener("click", (e) => {
  const chatItem = e.target.closest(".chat-item");
  if (!chatItem) return;

  // Remove active class from all chats
  document.querySelectorAll(".chat-item").forEach((item) => {
    item.classList.remove("active");
  });

  // Add active class to selected chat
  chatItem.classList.add("active");
  const selectedChat = chatItem.innerText.trim();
  currentChatName.innerText = selectedChat;
  messageInput.disabled = false;
  sendMessageBtn.disabled = false;
  pokeBtn.disabled = false;
  currentChat = selectedChat;

  // Load messages and start polling
  loadChatMessages(selectedChat, true); // true means scroll to bottom
  startMessagePolling(selectedChat);

  // After setting currentChat
  updateChatSettingsForRole();

  // New code - hide sidebar on mobile after selecting a chat
  if (window.innerWidth <= 576) {
    sidebar.classList.remove("visible");
    sidebarOverlay.classList.remove("visible");
  }
});

// Check screen size on resize to properly handle sidebar visibility
window.addEventListener("resize", () => {
  if (window.innerWidth > 576) {
    sidebar.classList.remove("visible");
    sidebarOverlay.classList.remove("visible");
  }
});

// Send message button listener
// Update send message button listener
sendMessageBtn.addEventListener("click", async () => {
  const chatName = currentChatName.innerText;
  const message = messageInput.value.trim();

  if (!message) {
    return; // Don't send empty messages
  }

  try {
    // Show optimistic UI update - clear the input first
    messageInput.value = "";

    // Create an optimistic message element right away
    const optimisticMsg = {
      content: message,
      sender: currentUsername,
      timestamp: new Date().toLocaleString(),
      id: "temp-" + Date.now(),
      type: 0x00,
      sender_uid: "local", // Temporary ID
    };

    // Add the optimistic message to the UI
    const msgElement = createMessageElement(optimisticMsg);
    msgElement.classList.add("optimistic");
    messagesContainer.appendChild(msgElement);

    // Scroll to show the new message
    messagesContainer.scrollTop = messagesContainer.scrollHeight;

    // Send the message
    const data = await API.sendMessage(authToken, chatName, message);

    if (data.opcode === 0x00) {
      // On success, remove the optimistic message class
      msgElement.classList.remove("optimistic");
      // Update messages without loading screen
      updateMessagesWithoutLoading(chatName, "send");
    } else {
      // On failure, mark the optimistic message as failed
      msgElement.classList.add("failed");
      showToast(API.getErrorMessage(0x10, data.error_opcode), "error");
    }
  } catch (error) {
    console.error("Send message error", error);
    showToast("Failed to send message. Please try again.", "error");
  }
});

// Add Enter key support to send messages
messageInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendMessageBtn.click();
  }
});

// Chat Settings: Remove User, Leave Chat, Delete Chat actions using prompt
removeUserBtn.addEventListener("click", async () => {
  const chatName = currentChatName.innerText;
  const username = prompt("Enter username to remove:");
  if (!username) return;
  try {
    const data = await API.removeUserFromChat(authToken, chatName, username);
    alert(
      data.opcode === 0x00 ? `User ${username} removed` : "Error removing user"
    );
  } catch (error) {
    console.error("Remove user error", error);
  }
});

leaveChatBtn.addEventListener("click", async () => {
  const chatName = currentChatName.innerText;
  if (confirm("Are you sure you want to leave this chat?")) {
    try {
      const data = await API.leaveChat(authToken, chatName);
      if (data.opcode === 0x00) {
        alert("You have left the chat");
        currentChatName.innerText = "Select a chat";
        messageInput.disabled = true;
        sendMessageBtn.disabled = true;
        // Optionally update chat list...
        loadChats();
      } else {
        alert("Error leaving chat");
      }
    } catch (error) {
      console.error("Leave chat error", error);
    }
  }
});

deleteChatBtn.addEventListener("click", async () => {
  const chatName = currentChatName.innerText;
  if (confirm("Delete chat? This cannot be undone.")) {
    try {
      const data = await API.deleteChat(authToken, chatName);
      if (data.opcode === 0x00) {
        alert("Chat deleted and removed from list");
        currentChatName.innerText = "Select a chat";
        messagesContainer.innerHTML = `<div class="empty-state">Select a chat or create a new one to start messaging</div>`;
        stopMessagePolling(); // Stop polling when chat is deleted
        loadChats(); // Refresh chat list
      } else {
        alert("Error deleting chat");
      }
    } catch (error) {
      console.error("Delete chat error", error);
    }
  }
});

// Open Role Management Modal on button click
manageRolesBtn.addEventListener("click", () => {
  // Only proceed if a chat is selected
  if (!currentChat) {
    alert("Please select a chat first");
    return;
  }

  // Populate role dropdowns before opening the modal
  populateRoleDropdowns();
  openModal(roleManagementModal);
});

// Function to fetch roles and populate the role dropdowns
async function populateRoleDropdowns() {
  if (!currentChat) return;
  try {
    const data = await API.getRoles(authToken, currentChat);
    if (data.opcode === 0x00) {
      const roleToAssignSelect = document.getElementById("roleToAssign");
      const roleToRemoveSelect = document.getElementById("roleToRemove");

      // Clear existing options
      roleToAssignSelect.innerHTML = "";
      roleToRemoveSelect.innerHTML = "";

      // Check if roles array exists and has elements
      if (data.roles && Array.isArray(data.roles) && data.roles.length > 0) {
        // Add roles to dropdowns
        data.roles.forEach((role) => {
          roleToAssignSelect.add(new Option(role, role));
          roleToRemoveSelect.add(new Option(role, role));
        });
      } else {
        // Add a placeholder option if no roles exist
        roleToAssignSelect.add(new Option("No roles available", ""));
        roleToRemoveSelect.add(new Option("No roles available", ""));
      }
    } else {
      console.error("Failed to fetch roles:", data.error_opcode);
      alert("Failed to load roles. Please try again.");
    }
  } catch (error) {
    console.error("Error fetching roles", error);
    alert("Error connecting to server. Please check your connection.");
  }
}

// Add a debugging function to show chat creator status
async function checkChatCreatorStatus() {
  if (!currentChat) return;
  try {
    const data = await API.getChats(authToken);
    if (data.opcode === 0x00 && data.chats) {
      const currentChatData = data.chats.find(
        (chat) => chat.name === currentChat
      );
      if (currentChatData) {
        console.log(`Current chat: ${currentChat}`);
        console.log(
          `You are ${
            currentChatData.is_owner ? "" : "not "
          }the creator of this chat`
        );
        return currentChatData.is_owner;
      }
    }
    return false;
  } catch (error) {
    console.error("Error checking chat creator status:", error);
    return false;
  }
}

// Role Management Tab Switching within the modal - fix existing implementation
roleManagementModal.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    roleManagementModal
      .querySelectorAll(".tab")
      .forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    roleManagementModal
      .querySelectorAll(".tab-pane")
      .forEach((pane) => pane.classList.add("hidden"));
    const tabContent = roleManagementModal.querySelector(
      `.tab-pane[data-tab="${tab.dataset.tab}"]`
    );
    if (tabContent) {
      tabContent.classList.remove("hidden");
    }
  });
});

// Create Role Form
createRoleForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const chatName = currentChatName.innerText;
  const roleName = document.getElementById("newRoleName").value.trim();
  if (!roleName) return alert("Enter a valid role name");
  try {
    const data = await API.createRole(authToken, chatName, roleName);
    if (data.opcode === 0x00) {
      alert(`Role ${roleName} created successfully`);
      document.getElementById("newRoleName").value = "";
      // Update the role dropdowns with the new role
      populateRoleDropdowns();
    } else {
      if (data.error_opcode === 0x49) {
        alert("Only the creator of the chat can create roles");
      } else if (data.error_opcode === 0x25) {
        alert("Role already exists or has an invalid name");
      } else {
        alert(`Error creating role: code ${data.error_opcode}`);
      }
    }
  } catch (error) {
    console.error("Create role error", error);
    alert("Failed to create role. Check your connection.");
  }
});

// Assign Role Form
assignRoleForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const chatName = currentChatName.innerText;
  const roleName = document.getElementById("roleToAssign").value;
  const usernameToAssign = document.getElementById("userToAssign").value.trim();
  if (!roleName || !usernameToAssign) return alert("Enter valid inputs");
  try {
    const data = await API.addRoleToUser(
      authToken,
      chatName,
      roleName,
      usernameToAssign
    );
    if (data.opcode === 0x00) {
      alert(`Role ${roleName} assigned to ${usernameToAssign} successfully`);
      document.getElementById("userToAssign").value = "";
    } else {
      if (data.error_opcode === 0x49) {
        alert("Only the creator of the chat can assign roles");
      } else if (data.error_opcode === 0x27) {
        alert("Role does not exist in this chat");
      } else if (data.error_opcode === 0x28) {
        alert("User does not exist or is not a member of this chat");
      } else {
        alert(`Error assigning role: code ${data.error_opcode}`);
      }
    }
  } catch (error) {
    console.error("Assign role error", error);
    alert("Failed to assign role. Check your connection.");
  }
});

// Remove Role Form
removeRoleForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const chatName = currentChatName.innerText;
  const roleName = document.getElementById("roleToRemove").value;
  const usernameToRemove = document
    .getElementById("userToRemoveFrom")
    .value.trim();
  if (!roleName || !usernameToRemove) return alert("Enter valid inputs");
  try {
    const data = await API.removeRoleFromUser(
      authToken,
      chatName,
      roleName,
      usernameToRemove
    );
    if (data.opcode === 0x00) {
      alert(`Role ${roleName} removed from ${usernameToRemove} successfully`);
      document.getElementById("userToRemoveFrom").value = "";
    } else {
      if (data.error_opcode === 0x49) {
        alert("Only the creator of the chat can remove roles");
      } else if (data.error_opcode === 0x30) {
        alert("Role does not exist or is not assigned to this user");
      } else if (data.error_opcode === 0x31) {
        alert("User does not exist or does not have this role");
      } else {
        alert(`Error removing role: code ${data.error_opcode}`);
      }
    }
  } catch (error) {
    console.error("Remove role error", error);
    alert("Failed to remove role. Check your connection.");
  }
});

// Open Chat Settings Modal on button click
chatSettingsBtn.addEventListener("click", async () => {
  console.log("Chat settings button clicked"); // Add this line for debugging
  if (!currentChat) {
    showToast("Please select a chat first", "error");
    return;
  }

  await updateChatSettingsForRole();
  openModal(chatSettingsModal);
});

// Ensure updateChatSettingsForRole function works properly
async function updateChatSettingsForRole() {
  console.log("Updating chat settings for role"); // Add this line for debugging
  const isCreator = await checkChatCreatorStatus();
  console.log("Is creator:", isCreator); // Add this line for debugging

  // Show/hide generate invite link button based on creator status
  if (isCreator) {
    generateInviteLinkBtn.style.display = "block";
    deleteChatBtn.style.display = "block";
    removeUserBtn.style.display = "block";
  } else {
    generateInviteLinkBtn.style.display = "none";
    deleteChatBtn.style.display = "none";
    removeUserBtn.style.display = "none";
  }

  // Always show leave chat button for non-creators
  leaveChatBtn.style.display = isCreator ? "none" : "block";
}

// Edit Message Modal
document
  .getElementById("messagesContainer")
  .addEventListener("dblclick", (e) => {
    const messageDiv = e.target.closest(".message");
    if (!messageDiv) return;

    // Only allow editing outgoing (your own) messages
    if (!messageDiv.classList.contains("outgoing")) return;
    
    // Extract message ID
    currentMessageId = messageDiv.dataset.messageId;
    if (!currentMessageId) {
      console.warn("Message ID not found");
      return;
    }

    // Populate the edit message input with the current message content
    const messageContent =
      messageDiv.querySelector(".message-content").innerText;
    document.getElementById("editMessageInput").value = messageContent;
    openModal(editMessageModal);
  });

cancelEditMessageBtn.addEventListener("click", () =>
  closeModal(editMessageModal)
);

// Update edit message form submission
editMessageForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!currentChat) {
    showToast("Select a chat first", "error");
    return;
  }

  const updatedMessage = document
    .getElementById("editMessageInput")
    .value.trim();

  if (!updatedMessage) {
    showToast("Message cannot be empty", "error");
    return;
  }

  try {
    // Close the modal first for better UX
    closeModal(editMessageModal);

    // Optimistically update the message text in the UI
    const messageElement = document.querySelector(
      `.message[data-message-id="${currentMessageId}"]`
    );

    if (messageElement) {
      const contentElement = messageElement.querySelector(".message-content");
      if (contentElement) {
        // Save old content in case we need to revert
        const oldContent = contentElement.innerHTML;
        // Update UI immediately
        contentElement.innerHTML = updatedMessage;

        // Add edited indicator if not already there
        const footer = messageElement.querySelector(".message-footer");
        if (footer && !footer.querySelector(".message-edited-indicator")) {
          const editedSpan = document.createElement("span");
          editedSpan.className = "message-edited-indicator";
          editedSpan.textContent = "(edited)";
          footer.insertBefore(editedSpan, footer.firstChild);
        }
      }
    }

    const data = await API.editMessage(
      authToken,
      currentChat,
      currentMessageId,
      updatedMessage
    );

    if (data.opcode === 0x00) {
      showToast("Message edited successfully", "success");
      // Update messages without loading screen
      updateMessagesWithoutLoading(currentChat, "edit");
    } else {
      // Revert optimistic update if there was an error
      if (messageElement && contentElement) {
        contentElement.innerHTML = oldContent;
      }

      const errorCode = data.error_opcode;
      if (errorCode === 0x19) {
        showToast("Invalid chat name", "error");
      } else if (errorCode === 0x20) {
        showToast("Invalid message ID", "error");
      } else if (errorCode === 0x49) {
        showToast("You don't have permission to edit this message", "error");
      } else {
        showToast(`Error editing message: code ${errorCode}`, "error");
      }
    }
  } catch (error) {
    console.error("Edit message error", error);
    showToast("Network error while editing message", "error");
  }
});

// Delete Message
messagesContainer.addEventListener("contextmenu", async (e) => {
  e.preventDefault();
  // This is a duplicate event handler, so we'll keep it simple and just return
  // The main contextmenu handler above will handle all context menu functionality
  return;
});

// Add periodic chat list refresh
function startChatListPolling() {
  setInterval(() => {
    if (authToken) {
      loadChats();
    }
  }, 10000); // Check for new chats every 10 seconds
}

// Start chat list polling after page load
document.addEventListener("DOMContentLoaded", () => {
  startChatListPolling();

  // Check if there's an invite link in URL
  const joinParam = getUrlParameter("join");
  if (joinParam) {
    // Store the invite link to use after login
    localStorage.setItem("pendingInviteLink", joinParam);
    // Show a message to user
    const inviteBanner = document.createElement("div");
    inviteBanner.className = "invite-banner";
    inviteBanner.innerHTML = `
      <span class="material-icons">link</span>
      <span>You've been invited to join a chat. Please log in to continue.</span>
    `;
    document.querySelector(".auth-container").prepend(inviteBanner);
    // Clean URL to remove the invite parameter
    window.history.replaceState({}, document.title, window.location.pathname);
  }

  // Try to restore session from localStorage
  const savedToken = localStorage.getItem("authToken");
  const savedUsername = localStorage.getItem("username");

  if (savedToken && savedUsername) {
    console.log("Restoring session from saved token");
    authToken = savedToken;
    currentUsername = savedUsername;
    refreshTokenIfNeeded(); // Check token age

    // Show main container
    authContainer.classList.add("hidden");
    mainContainer.classList.remove("hidden");

    // Load chats
    loadChats();
  }

  // Set up the Notion button
  const notionBtn = document.getElementById("notionBtn");
  if (notionBtn) {
    notionBtn.addEventListener("click", function () {
      // Replace with your actual Notion link
      window.open("https://www.notion.so", "_blank");
    });
  }
});

// Add a button to the sidebar to manage blocked users
const userInfo = document.querySelector(".user-info");
const manageBlockedBtn = document.createElement("button");
manageBlockedBtn.id = "manageBlockedBtn";
manageBlockedBtn.className = "btn icon-btn";
manageBlockedBtn.title = "Manage Blocked Users";
manageBlockedBtn.innerHTML = '<span class="material-icons">block</span>';
userInfo.appendChild(manageBlockedBtn);

manageBlockedBtn.addEventListener("click", async () => {
  await loadBlockedUsers();
  openModal(blockedUsersModal);
});

// Re-add event listener for generate invite link button to ensure it's connected
if (generateInviteLinkBtn) {
  console.log("Adding event listener to generate invite link button");
  generateInviteLinkBtn.addEventListener("click", async () => {
    console.log("Generate invite link button clicked");
    if (!currentChat) {
      showToast("No chat selected", "error");
      return;
    }

    try {
      showToast("Generating invite link...", "info");
      const data = await API.generateInviteLink(authToken, currentChat);

      if (data.opcode === 0x00) {
        // Create a shareable URL with the invite token (not exposing chat ID)
        const baseUrl = window.location.origin;
        // Use the token directly - it no longer contains the chat ID
        const fullInviteUrl = `${baseUrl}/?join=${encodeURIComponent(
          data.invite_link
        )}`;

        // Display the URL in the invite link modal
        const inviteLinkInput = document.getElementById("inviteLinkInput");
        if (inviteLinkInput) {
          inviteLinkInput.value = fullInviteUrl;
          closeModal(chatSettingsModal);
          openModal(document.getElementById("inviteLinkModal"));

          // Select the text for easy copying
          inviteLinkInput.select();

          // Reset event listeners to prevent duplicates
          const emailBtn = document.getElementById("emailInviteBtn");
          const smsBtn = document.getElementById("smsInviteBtn");

          // Clone and replace buttons to remove old event listeners
          const newEmailBtn = emailBtn.cloneNode(true);
          const newSmsBtn = smsBtn.cloneNode(true);
          emailBtn.parentNode.replaceChild(newEmailBtn, emailBtn);
          smsBtn.parentNode.replaceChild(newSmsBtn, smsBtn);

          // Add sharing functionality with fresh event listeners
          newEmailBtn.addEventListener("click", () => {
            const subject = "Join my chat on MessX";
            const body = `I've invited you to join a chat on MessX. Click this link to join: ${fullInviteUrl}`;
            window.open(
              `mailto:?subject=${encodeURIComponent(
                subject
              )}&body=${encodeURIComponent(body)}`
            );
          });

          newSmsBtn.addEventListener("click", () => {
            const message = `Join my chat on MessX: ${fullInviteUrl}`;
            // Check if device supports SMS links
            if (/Android|iPhone|iPad|iPod/i.test(navigator.userAgent)) {
              window.open(`sms:?&body=${encodeURIComponent(message)}`);
            } else {
              // Fallback for desktop
              showToast(
                "SMS sharing is only available on mobile devices",
                "info"
              );
              navigator.clipboard.writeText(message);
              showToast("Message copied to clipboard", "success");
            }
          });
        }
      } else {
        const errorCode = data.error_opcode;
        showToast(API.getErrorMessage("0x22", errorCode.toString(16)), "error");
      }
    } catch (error) {
      console.error("Error generating invite link:", error);
      showToast("Network error while generating invite link", "error");
    }
  });
} else {
  console.error("Generate invite link button not found in DOM");
}

// Copy invite link functionality with more clear user feedback
document.getElementById("copyInviteLinkBtn").addEventListener("click", () => {
  const inviteLinkInput = document.getElementById("inviteLinkInput");
  inviteLinkInput.select();

  try {
    // Try the modern clipboard API first
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard
        .writeText(inviteLinkInput.value)
        .then(() => {
          showCopiedFeedback();
        })
        .catch(() => {
          // Fall back to the older method if permission denied
          document.execCommand("copy");
          showCopiedFeedback();
        });
    } else {
      // Fall back for older browsers
      document.execCommand("copy");
      showCopiedFeedback();
    }
  } catch (err) {
    console.error("Failed to copy text: ", err);
    showToast("Failed to copy link", "error");
  }
});

// Helper function for copy feedback
function showCopiedFeedback() {
  // Change button text temporarily
  const copyBtn = document.getElementById("copyInviteLinkBtn");
  const originalText = copyBtn.textContent;
  copyBtn.textContent = "Copied!";
  copyBtn.disabled = true;

  setTimeout(() => {
    copyBtn.textContent = originalText;
    copyBtn.disabled = false;
  }, 2000);

  showToast("Secure invite link copied to clipboard", "success");
}

// Enhanced join chat by link functionality
async function joinChatViaInviteLink(inviteLink) {
  try {
    showToast("Joining chat...", "info");
    const data = await API.joinChatByLink(authToken, inviteLink);

    if (data.opcode === 0x00) {
      // Get chat that was joined
      const chatName = data.chat_name;

      // Show a welcome message
      const messagesContainer = document.querySelector(".messages-container");
      const welcomeBanner = document.createElement("div");
      welcomeBanner.className = "welcome-banner";
      welcomeBanner.innerHTML = `
        <span class="material-icons">celebration</span>
        <div>
          <strong>Welcome to ${chatName}!</strong>
          <p>You've successfully joined this chat via an invite link.</p>
        </div>
      `;
      messagesContainer.prepend(welcomeBanner);

      // Auto-remove the welcome banner after 10 seconds
      setTimeout(() => {
        if (welcomeBanner.parentNode) {
          welcomeBanner.parentNode.removeChild(welcomeBanner);
        }
      }, 10000);

      // Update the chat list and select the new chat
      await loadChats();
      switchChat(chatName);

      showToast(`Successfully joined chat: ${chatName}`, "success");
    } else {
      const errorCode = data.error_opcode;
      let errorMsg = API.getErrorMessage("0x23", errorCode.toString(16));
      showToast(`Failed to join chat: ${errorMsg}`, "error");
    }
  } catch (error) {
    console.error("Error joining chat via invite link:", error);
    showToast("Network error while joining chat", "error");
  }
}

// Enhanced invite link detection in URL
document.addEventListener("DOMContentLoaded", () => {
  // ...existing code...

  // Check if there's an invite link in URL
  const joinParam = getUrlParameter("join");
  if (joinParam) {
    // Create a more prominent invitation banner
    const inviteBanner = document.createElement("div");
    inviteBanner.className = "invite-banner";
    inviteBanner.innerHTML = `
      <span class="material-icons">groups</span>
      <div>
        <strong>You've been invited to join a chat!</strong>
        <p>Please log in or create an account to join the conversation.</p>
      </div>
    `;
    document.querySelector(".auth-container").prepend(inviteBanner);

    // Store the invite link to use after login
    try {
      localStorage.setItem("pendingInviteLink", decodeURIComponent(joinParam));
    } catch (e) {
      localStorage.setItem("pendingInviteLink", joinParam);
    }

    // Clean URL to remove the invite parameter
    window.history.replaceState({}, document.title, window.location.pathname);
  }
});

// Helper function to show toast notifications
function showToast(message, type = "info") {
  const toast = document.getElementById("toast");
  toast.innerHTML = "";

  // Add appropriate icon
  let iconName = "info";
  if (type === "success") iconName = "check_circle";
  else if (type === "error") iconName = "error";
  else if (type === "warning") iconName = "warning";

  const content = `
    <span class="toast-icon material-icons">${iconName}</span>
    <span class="toast-message">${message}</span>
  `;

  toast.innerHTML = content;
  toast.className = "toast"; // Reset classes

  // Add appropriate type class
  toast.classList.add(type);
  toast.classList.add("visible");

  // Auto-hide after 3 seconds
  setTimeout(() => {
    toast.classList.remove("visible");
  }, 3000);

  // Allow clicking to dismiss
  toast.addEventListener("click", () => {
    toast.classList.remove("visible");
  });
}

// Enhanced error handling function
function handleApiError(data, defaultMessage = "An error occurred") {
  if (!data) {
    showErrorModal(
      "Network Error",
      "Failed to connect to the server. Please check your internet connection."
    );
    return false;
  }

  const errorOpcode = data.error_opcode;
  const opcode = data.opcode;

  if (errorOpcode) {
    // Get user-friendly error message from API
    const errorMessage = API.getErrorMessage(
      opcode.toString(16),
      errorOpcode.toString(16)
    );

    // For authentication errors, show in modal
    if (errorOpcode === 0x48 || errorOpcode === 0x03) {
      // Special case for invalid credentials
      if (errorOpcode === 0x03 && opcode === 0x00) {
        showToast("Invalid username or password", "error");
        // Focus the password field for retry
        document.getElementById("loginPassword").focus();
        document.getElementById("loginPassword").select();
        return false;
      }

      showErrorModal("Authentication Error", errorMessage);
      // If it's an authentication error, also logout the user
      if (errorOpcode === 0x48) {
        logoutUser();
      }
    } else {
      // For other errors, use toast
      showToast(errorMessage, "error");
    }
    return false;
  }

  return true;
}

// Show error in modal for more serious errors
function showErrorModal(title, message) {
  document.getElementById("errorModalTitle").textContent = title;
  document.getElementById("errorModalMessage").textContent = message;
  openModal(document.getElementById("errorModal"));
}

// Force logout on authentication errors
function logoutUser() {
  // Small delay to show the error before logging out
  setTimeout(() => {
    authToken = null;
    currentUsername = null;
    mainContainer.classList.add("hidden");
    authContainer.classList.remove("hidden");
    stopMessagePolling();
    currentChat = null;
    currentMessageId = null;
  }, 2000);
}

// Function to parse URL parameters
function getUrlParameter(name) {
  name = name.replace(/[[]/, "\\[").replace(/[\]]/, "\\]");
  const regex = new RegExp("[\\?&]" + name + "=([^&#]*)");
  const results = regex.exec(location.search);
  return results === null
    ? ""
    : decodeURIComponent(results[1].replace(/\+/g, " "));
}

// Function to join a chat via invite link
async function joinChatViaInviteLink(inviteLink) {
  try {
    showToast("Joining chat...", "info");
    const data = await API.joinChatByLink(authToken, inviteLink);

    if (data.opcode === 0x00) {
      // Get chat that was joined
      const chatName = data.chat_name;

      // Show a welcome message
      const messagesContainer = document.querySelector(".messages-container");
      const welcomeBanner = document.createElement("div");
      welcomeBanner.className = "welcome-banner";
      welcomeBanner.innerHTML = `
        <span class="material-icons">celebration</span>
        <div>
          <strong>Welcome to ${chatName}!</strong>
          <p>You've successfully joined this chat via an invite link.</p>
        </div>
      `;
      messagesContainer.prepend(welcomeBanner);

      // Auto-remove the welcome banner after 10 seconds
      setTimeout(() => {
        if (welcomeBanner.parentNode) {
          welcomeBanner.parentNode.removeChild(welcomeBanner);
        }
      }, 10000);

      // Update the chat list and select the new chat
      await loadChats();
      switchChat(chatName);

      showToast(`Successfully joined chat: ${chatName}`, "success");
    } else {
      const errorCode = data.error_opcode;
      let errorMsg = API.getErrorMessage("0x23", errorCode.toString(16));
      showToast(`Failed to join chat: ${errorMsg}`, "error");
    }
  } catch (error) {
    console.error("Error joining chat via invite link:", error);
    showToast("Network error while joining chat", "error");
  }
}

// Function to block a username
async function blockUser(username) {
  try {
    const data = await API.blockUser(authToken, username);
    if (data.opcode === 0x00) {
      showToast(`User ${username} has been blocked`, "success");
      // Reload messages to apply the block
      if (currentChat) {
        loadChatMessages(currentChat);
      }
    } else {
      const errorCode = data.error_opcode;
      if (errorCode === 0x15) {
        showToast("User not found", "error");
      } else if (errorCode === 0x49) {
        showToast("You cannot block yourself", "error");
      } else {
        showToast(`Error blocking user: code ${errorCode}`, "error");
      }
    }
  } catch (error) {
    console.error("Error blocking user", error);
    showToast("Network error while blocking user", "error");
  }
}

// Add this after the blockUser function
async function unblockUser(username) {
  try {
    const data = await API.unblockUser(authToken, username);
    if (data.opcode === 0x00) {
      showToast(`User ${username} has been unblocked`, "success");
      // Reload messages to apply the unblock
      if (currentChat) {
        loadChatMessages(currentChat);
      }
    } else {
      const errorCode = data.error_opcode;
      if (errorCode === 0x16) {
        showToast("User not found", "error");
      } else {
        showToast(`Error unblocking user: code ${errorCode}`, "error");
      }
    }
  } catch (error) {
    console.error("Error unblocking user", error);
    showToast("Network error while unblocking user", "error");
  }
}

// Add this function to load blocked users
async function loadBlockedUsers() {
  try {
    const blockedUsersList = document.getElementById("blockedUsersList");
    blockedUsersList.innerHTML =
      '<div class="loading">Loading blocked users...</div>';
    const data = await API.getBlockedUsers(authToken);
    if (data.opcode === 0x00) {
      blockedUsersList.innerHTML = "";
      if (!data.blocked_users || data.blocked_users.length === 0) {
        blockedUsersList.innerHTML =
          '<div class="empty-state">No blocked users</div>';
        return;
      }
      data.blocked_users.forEach((username) => {
        const userItem = document.createElement("div");
        userItem.className = "blocked-user-item";
        userItem.innerHTML = `
          <span class="blocked-username">${username}</span>
          <button class="unblock-btn" data-username="${username}">
            <span class="material-icons">person_add</span> Unblock
          </button>
        `;
        blockedUsersList.appendChild(userItem);
      });

      // Add event listeners to unblock buttons
      document.querySelectorAll(".unblock-btn").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const username = btn.dataset.username;
          await unblockUser(username);
          // Reload the blocked users list
          loadBlockedUsers();
        });
      });
    } else {
      blockedUsersList.innerHTML =
        '<div class="error-state">Failed to load blocked users</div>';
    }
  } catch (error) {
    console.error("Error loading blocked users", error);
    document.getElementById("blockedUsersList").innerHTML =
      '<div class="error-state">Error connecting to server</div>';
  }
}

// Add new function to display read receipts modal
async function showReadReceipts(messageId) {
  try {
    // Show loading indication
    const deliveredList = document.getElementById("deliveredList");
    const readByList = document.getElementById("readByList");
    const msgSentTime = document.getElementById("msgSentTime");

    // Clear previous data
    deliveredList.innerHTML = "<li>Loading...</li>";
    readByList.innerHTML = "<li>Loading...</li>";
    msgSentTime.textContent = "Loading...";

    // Open the modal immediately to show loading state
    openModal(readReceiptsModal);

    const data = await API.getReadReceipts(authToken, currentChat, messageId);

    if (data.opcode === 0x00) {
      // Clear loading indicators
      deliveredList.innerHTML = "";
      readByList.innerHTML = "";

      // Format sent time
      let sentTime = "Unknown";
      if (data.sent_time) {
        if (typeof data.sent_time === "object" && data.sent_time.seconds) {
          // Handle Firestore timestamp object
          const date = new Date(data.sent_time.seconds * 1000);
          sentTime = date.toLocaleString();
        } else {
          // Handle string timestamp
          sentTime = data.sent_time;
        }
      }
      msgSentTime.textContent = sentTime;

      // Populate delivered list
      if (data.delivered_to && data.delivered_to.length > 0) {
        data.delivered_to.forEach((user) => {
          const li = document.createElement("li");
          // Only display username and hide UIDs
          const displayName = user.username;
          li.innerHTML = `
            <span class="username">${displayName}</span>
            <span class="timestamp">${user.time || ""}</span>
          `;
          deliveredList.appendChild(li);
        });
      } else {
        deliveredList.innerHTML = "<li>Not yet delivered</li>";
      }

      // Populate read list
      if (data.read_by && data.read_by.length > 0) {
        data.read_by.forEach((user) => {
          const li = document.createElement("li");
          li.innerHTML = `
            <span class="username">${user.username}</span>
            <span class="timestamp">${user.time || ""}</span>
          `;
          readByList.appendChild(li);
        });
      } else {
        readByList.innerHTML = "<li>Not yet read</li>";
      }
    } else {
      // Show error in the modal
      deliveredList.innerHTML = "<li>Error loading delivered info</li>";
      readByList.innerHTML = "<li>Error loading read info</li>";
      showToast("Failed to load read receipts", "error");
    }
  } catch (error) {
    console.error("Error loading read receipts", error);
    // Show error in the modal
    document.getElementById("deliveredList").innerHTML =
      "<li>Network error</li>";
    document.getElementById("readByList").innerHTML = "<li>Network error</li>";
    showToast("Network error while loading read receipts", "error");
  }
}

// Fix the message scroll handling to use debouncing with optimized read marking
const debouncedHandleMessagesScroll = debounce(function () {
  if (!currentChat || !authToken) return;

  const messages = document.querySelectorAll(
    ".message.incoming:not(.read-marked)"
  );
  const newMessagesToMark = [];

  messages.forEach((messageDiv) => {
    const rect = messageDiv.getBoundingClientRect();
    const isInViewport = rect.top >= 0 && rect.bottom <= window.innerHeight;

    if (isInViewport) {
      const messageId = messageDiv.dataset.messageId;
      if (messageId) {
        newMessagesToMark.push(messageId);
        messageDiv.classList.add("read-marked");
      }
    }
  });

  if (newMessagesToMark.length > 0) {
    pendingReadMessages = [...pendingReadMessages, ...newMessagesToMark];

    // If there are many pending messages, process them immediately
    if (pendingReadMessages.length > 5) {
      processPendingReadReceipts();
    }
  }
}, 300);

// Add the scroll event listener to handle message visibility
messagesContainer.addEventListener("scroll", debouncedHandleMessagesScroll);

// Add the following function near your message processing logic to handle decryption failures gracefully

// Inside your app.js, look for the section where you load chat messages
// Add this function near that code (it's only shown as a snippet that should be added)

function handleEncryptedMessage(messageContent) {
  // If the message appears to be encrypted but couldn't be decrypted
  if (messageContent === "[Encrypted message - cannot decrypt]") {
    // Try to initialize keys if needed
    (async () => {
      const userKeys = await AuthUtils.getUserKeys();
      if (!userKeys) {
        // Try to generate new keys if they don't exist
        await AuthUtils.generateAndStoreUserKeys();
      }
    })();

    return `<div class="encrypted-message-notice">
              <span class="material-icons">lock</span>
              This message is encrypted and cannot be decrypted with your current keys.
            </div>`;
  }

  // Regular message content
  return messageContent;
}

// Add a missing switchChat function after the loadChats function
function switchChat(chatName) {
  if (!chatName) return;

  // Find the chat item in the list
  const chatItems = document.querySelectorAll(".chat-item");
  let chatFound = false;

  chatItems.forEach((item) => {
    if (item.innerText.trim() === chatName) {
      // Trigger a click on this chat item
      item.click();
      chatFound = true;
    }
  });

  if (!chatFound) {
    console.warn(`Chat "${chatName}" not found in the list`);
    showToast(`Could not find chat "${chatName}"`, "warning");

    // Force refresh the chat list to make sure it's up to date
    loadChats().then(() => {
      // Try again after reloading
      setTimeout(() => {
        const updatedChatItems = document.querySelectorAll(".chat-item");
        updatedChatItems.forEach((item) => {
          if (item.innerText.trim() === chatName) {
            item.click();
          }
        });
      }, 500);
    });
  }
}

// Improve batch read receipt processing (replace existing interval)
let readReceiptProcessingInterval = null;
function startReadReceiptProcessing() {
  // Clear any existing interval
  if (readReceiptProcessingInterval) {
    clearInterval(readReceiptProcessingInterval);
  }

  // Process pending read receipts every 1.5 seconds
  readReceiptProcessingInterval = setInterval(processPendingReadReceipts, 1500);
}

// Call this at page load to start the processing
startReadReceiptProcessing();

// Initialize the blocked users modal if it doesn't exist
document.addEventListener("DOMContentLoaded", () => {
  // Check if blocked users modal exists, if not create it
  if (!document.getElementById("blockedUsersModal")) {
    const blockedUsersModal = document.createElement("div");
    blockedUsersModal.className = "modal";
    blockedUsersModal.id = "blockedUsersModal";
    blockedUsersModal.innerHTML = `
      <div class="modal-content">
        <h3>Blocked Users</h3>
        <div class="blocked-users-list" id="blockedUsersList">
          <!-- Blocked users will be listed here -->
        </div>
        <div class="modal-actions">
          <button type="button" class="btn secondary close-modal">Close</button>
        </div>
      </div>
    `;
    document.body.appendChild(blockedUsersModal);
  }

  // Check if invite link modal exists, if not create it
  if (!document.getElementById("inviteLinkModal")) {
    const inviteLinkModal = document.createElement("div");
    inviteLinkModal.className = "modal";
    inviteLinkModal.id = "inviteLinkModal";
    inviteLinkModal.innerHTML = `
      <div class="modal-content">
        <h3>Invite Link</h3>
        <p class="invite-link-instructions">Share this link with others to invite them to this chat:</p>
        <div class="invite-link-container">
          <input type="text" id="inviteLinkInput" readonly />
          <button id="copyInviteLinkBtn" class="btn primary">Copy</button>
        </div>
        <div class="invite-link-sharing">
          <button id="emailInviteBtn" class="btn btn-share">
            <span class="material-icons">email</span> Email
          </button>
          <button id="smsInviteBtn" class="btn btn-share">
            <span class="material-icons">sms</span> SMS
          </button>
        </div>
        <div class="modal-actions">
          <button type="button" class="btn secondary close-modal">Close</button>
        </div>
      </div>
    `;
    document.body.appendChild(inviteLinkModal);
  }

  // Initialize any missing event listeners
  document.querySelectorAll(".close-modal").forEach((btn) => {
    btn.addEventListener("click", () => {
      btn.closest(".modal").classList.remove("active");
    });
  });

  // Add error modal if it doesn't exist
  if (!document.getElementById("errorModal")) {
    const errorModal = document.createElement("div");
    errorModal.className = "modal";
    errorModal.id = "errorModal";
    errorModal.innerHTML = `
      <div class="modal-content">
        <h3 id="errorModalTitle">Error</h3>
        <div class="error-container">
          <div class="error-icon">
            <span class="material-icons">error</span>
          </div>
          <div id="errorModalMessage">An error occurred.</div>
        </div>
        <div class="modal-actions">
          <button type="button" class="btn secondary close-modal">Close</button>
        </div>
      </div>
    `;
    document.body.appendChild(errorModal);
  }

  // Add event listener for the copy button if it exists
  const copyBtn = document.getElementById("copyInviteLinkBtn");
  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      const inviteLinkInput = document.getElementById("inviteLinkInput");
      if (inviteLinkInput) {
        inviteLinkInput.select();
        document.execCommand("copy");
        showToast("Link copied to clipboard!", "success");
      }
    });
  }

  // Start polling for read receipts
  startReadReceiptProcessing();
});

// Add this function to app.js
function updateClocks() {
  const now = new Date();

  // UTC time
  const utcString = now.toUTCString();
  const utcTime = utcString.split(" ")[4];
  document.getElementById("utcClock").textContent = utcTime;

  // IST (Indian Standard Time, UTC+5:30)
  const istOptions = {
    timeZone: "Asia/Kolkata",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  };
  document.getElementById("istClock").textContent = now.toLocaleTimeString(
    "en-US",
    istOptions
  );

  // CST (Central Standard Time, UTC-6:00)
  const cstOptions = {
    timeZone: "America/Chicago",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  };
  document.getElementById("cstClock").textContent = now.toLocaleTimeString(
    "en-US",
    cstOptions
  );
}

// Update the clocks every second
setInterval(updateClocks, 1000);

// Initialize the clocks when the page loads
document.addEventListener("DOMContentLoaded", function () {
  updateClocks();
  // Your other existing initialization code...
});

// Add these variables near the top with other globals
let currentMessageLimit = 20; // Initial message load count
const MESSAGE_BATCH_SIZE = 20; // How many more messages to load each time

// New function to handle loading more messages
async function loadMoreMessages() {
  if (!currentChat) return;

  // Update button to show loading state
  const loadMoreBtn = document.getElementById("loadMoreMessagesBtn");
  if (loadMoreBtn) {
    loadMoreBtn.innerHTML = '<span class="loading-spinner"></span> Loading...';
    loadMoreBtn.disabled = true;
  }

  // Store current scroll position and height
  const scrollPos = messagesContainer.scrollTop;
  const oldHeight = messagesContainer.scrollHeight;

  // Increase the message limit
  currentMessageLimit += MESSAGE_BATCH_SIZE;

  try {
    const data = await API.getMessages(
      authToken,
      currentChat,
      currentMessageLimit
    );

    if (data.opcode === 0x00) {
      // Clear existing messages container
      messagesContainer.innerHTML = "";

      // Handle case when there are no messages
      if (!data.messages || data.messages.length === 0) {
        messagesContainer.innerHTML = `<div class="empty-state">No messages yet</div>`;
        return;
      }

      // Reverse messages to show in chronological order (oldest first)
      const chronologicalMessages = [...data.messages].reverse();

      // Add the "Load More" button if there are likely more messages
      if (chronologicalMessages.length >= currentMessageLimit) {
        const newLoadMoreBtn = createLoadMoreButton();
        messagesContainer.appendChild(newLoadMoreBtn);
      }

      // Display messages
      const messagesToMarkAsRead = [];
      chronologicalMessages.forEach((msg) => {
        if (
          msg.sender !== currentUsername &&
          !msg.read_by?.find((entry) => entry.username === currentUsername)
        ) {
          messagesToMarkAsRead.push(msg.id);
        }
        const div = createMessageElement(msg);
        messagesContainer.appendChild(div);
      });

      // Add messages to be marked as read to the pending queue
      if (messagesToMarkAsRead.length > 0) {
        pendingReadMessages = [...pendingReadMessages, ...messagesToMarkAsRead];
      }

      // Restore scroll position approximately where user was before
      const newHeight = messagesContainer.scrollHeight;
      messagesContainer.scrollTop = scrollPos + (newHeight - oldHeight);
    } else {
      handleApiError(data, "Failed to load more messages");
    }
  } catch (error) {
    console.error("Error loading more messages", error);
    showToast("Failed to load more messages. Check your connection.", "error");
  }
}

// Function to create the Load More button
function createLoadMoreButton() {
  const loadMoreBtn = document.createElement("button");
  loadMoreBtn.id = "loadMoreMessagesBtn";
  loadMoreBtn.className = "btn load-more-btn";
  loadMoreBtn.innerHTML = "Load More Messages";
  loadMoreBtn.addEventListener("click", loadMoreMessages);
  return loadMoreBtn;
}
