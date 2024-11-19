// Function to close the alert manually
function closeAlert() {
  document.getElementById("alert").style.display = 'none';
  clearTimeout(alertTimeout); // Clear the timeout if the user closes the alert early
}

// Set a timeout to close the alert after 10 seconds
let alertTimeout = setTimeout(function() {
  closeAlert();
}, 5000); // 10 seconds