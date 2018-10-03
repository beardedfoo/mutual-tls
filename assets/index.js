fetch("https://" + document.location.hostname + ":8000/me").then(function(result) {
  return result.json();
}).then(function(result) {
  console.log(result)
})
