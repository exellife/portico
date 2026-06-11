// Shared site script: highlight the active nav link. Served static + precompressed.
(function () {
  var path = location.pathname.replace(/index\.html$/, "");
  document.querySelectorAll("nav a.link").forEach(function (a) {
    var href = a.getAttribute("href");
    if (href === path || (href !== "/" && path.indexOf(href) === 0)) a.classList.add("active");
    if (path === "/" && href === "/") a.classList.add("active");
  });
})();
