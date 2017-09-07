package registry

const (
	viewsHelpers = `
function key(version) {
  var vs = version.split(".");
  return [
    parseInt(vs[0], 10),
    parseInt(vs[1], 10),
    parseInt(vs[2], 10),
  ];
}
function getVersionChannel(version) {
  if (version.indexOf("-dev.") >= 0) {
    return "dev";
  }
  if (version.indexOf("-beta.") >= 0) {
    return "beta";
  }
  return "stable";
}`

	devView = `
function(doc) {
  ` + viewsHelpers + `
  var version = doc.version;
  var channel = getVersionChannel(version);
  if (channel == "dev") {
    emit(key(version.split("-dev.")[0]));
  } else if (channel == "beta") {
    emit(key(version.split("-beta.")[0]));
  } else {
    emit(key(version));
  }
}`

	betaView = `
function(doc) {
  ` + viewsHelpers + `
  var version = doc.version;
  var channel = getVersionChannel(version);
  if (channel == "beta") {
    emit(key(version.split("-beta.")[0]));
  } else if (channel == "stable") {
    emit(key(version));
  }
}`

	stableView = `
function(doc) {
  ` + viewsHelpers + `
  var version = doc.version;
  var channel = getVersionChannel(version);
  if (channel == "stable") {
    emit(key(version));
  }
}`
)
