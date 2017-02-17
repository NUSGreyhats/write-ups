# NUS Greyhats' write up repository

## Branches
gh-pages branch contains contents of _site folder.
master branch contains jekyll files and templates.

## To write a post
1. `git fetch --all`
1. `git pull --all`
1. Checkout into master branch.
1. Write post in _post folder.
1. Run jekyll build locally on your own machine.
1. Commit to master branch when done.
1. cd to _site folder.
1. Touch .nojekyll file to prevent github from generating any files.
1. `git pull`
1. `git checkout gh-pages`
1. `git add .`
1. `git commit -m "message"`

And you're done.
