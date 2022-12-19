var source = new EventSource('/Log_Activity');
source.onmessage = function(event) {
  console.log(event.data);
  // Update the page with the new data
};


function redirect() {
    window.location.href = 'https://www.google.com'; // redirect to the specified URL
  }
  
