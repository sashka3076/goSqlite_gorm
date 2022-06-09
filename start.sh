
cd $HOME/MyWork/webssh2/app
tmux new -s s -d
tmux send -t "s" "./run.sh" Enter
tmux new -s ss -d
cd $HOME/MyWork/goSqlite_gorm
tmux send -t "ss" "./main" Enter


