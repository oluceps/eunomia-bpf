const { data: releases } = await github.repos.listReleases({
  owner: context.repo.owner,
  repo: context.repo.repo,
});

async function get_release_commit_sha(release) {

  const { data: release_commit } = await github.repos.listCommits({
    owner: context.repo.owner,
    repo: context.repo.repo,
    sha: release.target_commitish,
  });
  console.log("release commit sha:" + release_commit[0].sha);
  return release_commit[0].sha;
}

if (releases.length === 0) { return "v0.0.1"; }

async function getReleaseForCommitSha(commitSha) {
  const { owner, repo } = context.repo;
  const { data: releases } = await github.repos.listReleases({ owner, repo });
  return releases.find(release =>  get_release_commit_sha(release) === commitSha );
}

function increase_v(version) {
  const parts = version.split(".");
  const last = parseInt(parts[2]) + 1;
  const next_version = `${parts[0]}.${parts[1]}.${last.toString()}`;
  return next_version;
}

console.log("now context.sha: " + context.sha);
const coresp_release = await getReleaseForCommitSha(context.sha);
const latest_release_tag = releases[0].tag_name;
console.log("coresp_release: " + coresp_release);
console.log("latest_release_tag: " + latest_release_tag);

if (coresp_release === undefined) {
  return increase_v(latest_release_tag)
}

const coresp_release_tag = coresp_release.tag_name;

console.log("coresponding release tag is: " + coresp_release_tag)
console.log("SHA of this commit: " + sha)

return latest_release_tag
