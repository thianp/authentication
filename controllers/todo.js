// P'EARTN CONTROLLER. FOR COMPARE WITH MY OWN CONTROLLER 
const createError = require("../utils/createError");
const { Todo, User } = require("../models"); //must bracket as it is object model

exports.createTodo = async (req, res, next) => {
  try {
    // const body = req.body;
    const { title, completed, dueDate } = req.body; //destructure
    //Create new Todo
    await Todo.create({ title: title, completed: completed, dueDate: dueDate });
    res.status(201).json({
      message:
        "create Todo success. this is responding message from todoController",
    });
  } catch (err) {
    next(err);
  }
};

exports.getAllTodo = async (req, res, next) => {
  try {
    const { userId } = req.body;
    const todos = await Todo.findAll({ where: { userId: userId } });
    res.json({ todos: todos });
  } catch (err) {
    next(err);
  }
};

exports.getTodoById = async (req, res, next) => {
  try {
    const { userId } = req.body;
    const todo = await Todo.findOne({
      where: { id: req.params.id, userId: userId },
    });
    res.json({ todo: todo });
  } catch (err) {
    next(err);
  }
};

// exports.updateTodo = async (req, res, next) => {
//   try {
//     const { id, title, completed, dueDate } = req.body; //destructure
//     //---------------------------------------------------------------------------------
//     const todo = await Todo.findOne({ where: { id: id } }); //เอามา row เดียว
//     if (!todo) {
//       createError("todo is not found", 400);
//     }
//     //---------------------------------------------------------------------------------
//     await Todo.update(
//       { title: title, completed: completed, dueDate: dueDate },
//       { where: { id: id } }
//     );
//     res.status(201).json({
//       message:
//         "update todo success. this is responding message from todoController",
//     });
//     //---------------------------------------------------------------------------------
//   } catch (err) {
//     next(err);
//   }
// };

//Aj version
exports.updateTodo = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { userId, title, completed, dueDate } = req.body; //destructure
    //---------------------------------------------------------------------------------

    //---------------------------------------------------------------------------------
    const result = await Todo.update(
      { title: title, completed: completed, dueDate: dueDate },
      { where: { id: id, userId: userId } }
    );
    if (result[0] === 0) {
      createError("Todo with this id is not found", 400);
    }
    res.status(201).json({
      message:
        "update todo success. this is responding message from todoController",
    });
    //---------------------------------------------------------------------------------
  } catch (err) {
    next(err);
  }
};

// exports.deleteTodo = async (req, res, next) => {
//   try {
//     const { id } = req.body; //destructure
//     const idd = await Todo.findOne({ where: { id: id } }); //เอามา row เดียว
//     if (!idd) {
//       createError("todo is not found", 400);
//     }
//     await Todo.destroy({
//       where: {
//         id: id,
//       },
//     });

//     res.status(201).json({
//       message:
//         "delete todo success. this is responding message from userController",
//     });
//   } catch (err) {
//     next(err);
//   }
// };

//Aj version
exports.deleteTodo = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { userId } = req.body; //destructure
    const result = await Todo.destroy({ where: { id: id, userId: userId } }); //เอามา row เดียว
    if (result === 0) {
      createError("todo is not found", 400);
    }
    res.status(204).json();
  } catch (err) {
    next(err);
  }
};