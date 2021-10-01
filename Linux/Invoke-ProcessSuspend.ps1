function Invoke-ProcessSuspend ($id){
    kill -STOP $id 
}

function Invoke-ResumeProcess ($id){
    kill -CONT $id
}
