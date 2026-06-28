document.querySelectorAll(".toolbar .filter").forEach(function (btn) {
  btn.addEventListener("click", function () {
    document.querySelectorAll(".toolbar .filter").forEach(function (b) {
      b.classList.remove("active");
    });
    btn.classList.add("active");
    var sev = btn.dataset.sev;

    document.querySelectorAll(".file").forEach(function (file) {
      var sevs = (file.dataset.sevs || "").split(",");
      var show = sev === "all" || sevs.indexOf(sev) !== -1;
      file.style.display = show ? "" : "none";

      file.querySelectorAll("tbody tr").forEach(function (row) {
        var match = sev === "all" || row.dataset.sev === sev;
        row.style.display = match ? "" : "none";
      });
      if (sev !== "all" && show) file.classList.add("open");
    });
  });
});
