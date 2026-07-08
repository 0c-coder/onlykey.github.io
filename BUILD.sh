#!/bin/bash

#get last submitted version
git checkout -- ./docs
lastVersionNumber=$(node -e 'console.log(require(__dirname+"/docs/release.js").version)')
lastVersionStage=$(node -e 'console.log(require(__dirname+"/docs/release.js").stage)')
lastStage=${lastVersionStage}${lastVersionNumber}

currentVersionNumber=$(node -e 'console.log(require(__dirname+"/src/release.js").version)')
currentVersionStage=$(node -e 'console.log(require(__dirname+"/src/release.js").stage)')
currentStage=${currentVersionStage}${currentVersionNumber}

#remove last submitted version
rm -rf ./docs


if [ "$currentStage" == "$lastStage"  ]; then
echo "Build Version Same"
echo "lastStage ${lastStage}"
echo "currentStage ${currentStage}"
else
echo "Build Version Different"
echo "lastStage ${lastStage}"
echo "currentStage ${currentStage}"
fi

#clear build dir
rm -rf ./build

#do build
if [ "$1" == "1" ]; then
echo "Build Production"
npm run build-release
else
npm run build-site

#build theme css

#cd ./src/bootstrap
#bash ./build-bootstrap.sh
#cd ../..

fi


#copy assets
cp -a ./src/assets/* ./build/app/.
cp -a ./src/assets/*.ico ./build/.
cp -a ./src/release.js ./build/.

# past_releases removed — no longer shipped with the OnlyAgent app


#complete by moving build dir to docs
mv ./build ./docs
# node ./docs/past_releases/build.past_releases.list.js
#rm ./docs/past_releases/build.past_releases.list.js


# else
# echo "Build Version Different"
# fi

# exit 2


echo onlyagent.app > ./docs/CNAME
touch ./docs/.nojekyll
