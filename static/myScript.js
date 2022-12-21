

var source = new EventSource('/Log_Activity');
source.onmessage = function(event) {
  console.log(event.data);
  // Update the page with the new data
};


function reportRedirect() {
    window.location.href = 'report'; // redirect to the specified URL
  }
  
 
function aaRedirect() {
}

function logActivityRedirect() {
    window.location.href = 'LogActivity'; // redirect to the specified URL
  }

  $(document).ready(function() {
    // Show the password prompt when the start button is clicked
    $('#start-button').click(function() {
      // Show the password prompt
      var password = prompt("Enter the sudo password:");
  
      // Make the AJAX request to start the packet
      $.ajax({
        url: '/start',
        data: { 'password': password },
        type: 'POST',
        success: function(response) {
          if (response == "Incorrect password") {
            alert(response);
          } else {
            $('#result').html(response);
          }
        }
      });
    });
  });
   
    

  function stopPacket() {
    $.ajax({
      url: '/stop',
      success: function(response) {
        $('#result').html(response);
        alert('Stopped Successfully');
        return 0;
      }
    });
  }


  $(document).ready(function() {
    $('#report-button').click(function() {
      // Make the AJAX request to get the packet info
      $.ajax({
        url: '/packet_info',
        type: 'GET',
        success: function(response) {
          // Update the table with the packet info
          for (var i = 0; i < response.length; i++) {
            var packet = response[i];
            var tr = $('<tr>');
            tr.append($('<td>').html(packet.source_ip));
            tr.append($('<td>').html(packet.source_port));
            tr.append($('<td>').html(packet.destination_ip));
            tr.append($('<td>').html(packet.destination_port));
            $('#packet-info-table').append(tr);
          }
  
          // Show the packet info table
          $('#packet-info-table').show();
        }
      });
    });
  });
  